(*
 * Copyright (c) 2015-2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

module Config = struct
  open Sexplib.Conv
  open Sexplib.Std

  type host = {
    hostname : string;
    options : Dhcp_wire.dhcp_option list;
    fixed_addr : Ipaddr_sexp.V4.t option;
    hw_addr : Macaddr_sexp.t;
  } [@@deriving sexp]

  type t = {
    options : Dhcp_wire.dhcp_option list;
    hostname : string;
    default_lease_time : int32;
    max_lease_time : int32;
    ip_addr : Ipaddr_sexp.V4.t;
    mac_addr : Macaddr_sexp.t;
    network : Ipaddr_sexp.V4.Prefix.t;
    range : (Ipaddr_sexp.V4.t * Ipaddr_sexp.V4.t) option;
    hosts : host list;
  } [@@deriving sexp]

  let t1_time_ratio = 0.5
  let t2_time_ratio = 0.8

  let lease_time_good config time = time <= config.max_lease_time

  let sanity_check config =
    (* Check if fixed addresses make sense *)
    List.iter (fun host ->
        match host.fixed_addr with
        | None -> ()
        | Some addr ->
          if not (Ipaddr.V4.Prefix.mem addr config.network) then
            invalid_arg (Printf.sprintf "Fixed address %s does not \
                                         belong to subnet %s"
                           (Ipaddr.V4.to_string addr)
                           (Ipaddr.V4.Prefix.to_string config.network))
          else match config.range with
               | None -> ()
               | Some range ->
                  if Util.addr_in_range addr range then
                    let low = fst range in
                    let high = snd range in
                    invalid_arg (Printf.sprintf "Fixed address %s must be \
                                                 outside of range %s:%s"
                                                (Ipaddr.V4.to_string addr)
                                                (Ipaddr.V4.to_string low)
                                                (Ipaddr.V4.to_string high)))
      config.hosts;
    config

  let make
      ?(hostname = "charrua-dhcp-server")
      ?(default_lease_time = 60 * 60 * 2) (* 2 hours *)
      ?(max_lease_time = 60 * 60 * 24)    (* 24 hours *)
      ?(hosts = [])
      ~addr_tuple
      ~network
      ~range
      ~options =

    let open Dhcp_wire in
    (* Try to ensure the user doesn't pass bad options *)
    let () =
      List.iter (function
          | Subnet_mask _ | Renewal_t1 _ | Rebinding_t2 _ | Client_id _
          | Ip_lease_time _ | End | Pad | Request_ip _ | Parameter_requests _
          as option ->
            invalid_arg (Printf.sprintf "option %s is not allowed"
                           (dhcp_option_to_string option))
          | _ -> ())
        options
    in
    (* Prepend a Subnet_mask, since we can always infer that from the network,
       the user doesn't need to specify, it must always come first in case there
       is a Router option later on RFC2132 3.3 *)
    let options = Subnet_mask (Ipaddr.V4.Prefix.netmask network) :: options in
    let ip_addr = fst addr_tuple in
    let mac_addr = snd addr_tuple in
    sanity_check {
      options;
      hostname;
      default_lease_time = Int32.of_int default_lease_time;
      max_lease_time = Int32.of_int max_lease_time;
      ip_addr;
      mac_addr;
      network;
      range;
      hosts;
    }

  let config_of_ast addr_tuple (ast : Ast.t) =
    let ip_addr = fst addr_tuple in
    let mac_addr = snd addr_tuple in
    let subnets = ast.Ast.subnets in
    let subnet = List.find
        (fun s -> Ipaddr.V4.Prefix.mem ip_addr s.Ast.network)
        subnets
    in
    let hosts = List.map (fun h ->
          { hostname = h.Ast.hostname;
            options = h.Ast.options;
            fixed_addr = h.Ast.fixed_addr;
            hw_addr = h.Ast.hw_addr;
          }) subnet.Ast.hosts
    in
    let default_lease_time = Util.some_or_default
        subnet.Ast.default_lease_time ast.Ast.default_lease_time
    in
    let max_lease_time = Util.some_or_default
        subnet.Ast.max_lease_time ast.Ast.max_lease_time
    in
    let network = subnet.Ast.network in

    (* Prepend a Subnet_mask, since we can always infer that from the network,
       the user doesn't need to specify, it must always come first in case there
       is a Router option later on, RFC2132 3.3. subnet.Ast.options must come
       first, this way we make sure we hit the more specific option when
       searching for a single entry. *)
    let options = Dhcp_wire.Subnet_mask (Ipaddr.V4.Prefix.netmask network) ::
                  (subnet.Ast.options @ ast.Ast.options)
    in
    sanity_check {
      options;
      hostname = "charrua-dhcp-server"; (* XXX Implement server-name option. *)
      default_lease_time;
      max_lease_time;
      ip_addr;
      mac_addr;
      network = subnet.Ast.network;
      range = subnet.Ast.range;
      hosts = hosts;
    }

  let parse configtxt addr_tuple =
    let choke lex s =
      let open Lexing in
      let pos = lex.lex_curr_p in
      let str = Printf.sprintf "%s at line %d around `%s`"
          s pos.pos_lnum (Lexing.lexeme lex)
      in
      invalid_arg str
    in
    let lex = Lexing.from_string configtxt in
    let ast =
      try Dhcp_parser.main Dhcp_lexer.lex lex with
      | Dhcp_parser.Error -> choke lex "Parser Error"
      | Invalid_argument e -> choke lex e
    in
    config_of_ast addr_tuple ast

end

module Lease = struct

  open Sexplib.Conv
  open Sexplib.Std

  module Client_id = struct
    open Dhcp_wire

    type t = client_id

    let compare a b =
      match a, b with
      | Hwaddr maca,  Hwaddr macb -> Macaddr.compare maca macb
      | Id ida,  Id idb -> String.compare ida idb
      | Id _, Hwaddr _ -> -1
      | Hwaddr _, Id _ -> 1
  end

  module Addr_map = Map.Make(Ipaddr.V4)
  module Id_map = Map.Make(Client_id)

  (* Lease (dhcp bindings) operations *)
  type t = {
    tm_start   : int32;
    tm_end     : int32;
    addr       : Ipaddr_sexp.V4.t;
    client_id  : Dhcp_wire.client_id;
  } [@@deriving sexp]

  let to_string lease = Sexplib.Sexp.to_string_hum (sexp_of_t lease)

  (* Database, collection of leases *)
  type database = {
    id_map : t Id_map.t;
    addr_map : t Addr_map.t;
  } (* with sexp *)

  let update_db id_map addr_map =
    { id_map; addr_map }

  let make_db () = update_db Id_map.empty Addr_map.empty

  let to_list db = Id_map.fold (fun id lease l -> lease :: l) db.id_map []

  let make client_id addr ~duration ~now =
    let tm_start = now in
    let tm_end = Int32.add tm_start duration in
    { tm_start; tm_end; addr; client_id }

  let make_fixed mac addr ~duration ~now =
    make (Dhcp_wire.Hwaddr mac) addr ~duration ~now

  let timeleft lease ~now =
    let left = Int32.sub lease.tm_end now in
    if left < Int32.zero then Int32.zero else left

  let timeleft_exn lease ~now =
    let left = timeleft lease ~now in
    if left = Int32.zero then invalid_arg "No time left for lease" else left

  let timeleft3 lease t1_ratio t2_ratio ~now =
    let left = Int32.to_float (timeleft lease ~now) in
    (Int32.of_float left,
     Int32.of_float (left *. t1_ratio),
     Int32.of_float (left *. t2_ratio))

  let extend lease ~now =
    let original = Int32.sub lease.tm_end lease.tm_start in
    make lease.client_id lease.addr ~duration:original ~now

  let expired lease ~now = timeleft lease ~now = Int32.zero

  let garbage_collect db ~now =
    update_db
      (Id_map.filter (fun _ lease -> not (expired lease ~now)) db.id_map)
      (Addr_map.filter (fun _ lease -> not (expired lease ~now)) db.addr_map)

  let lease_of_client_id client_id db = Util.find_some @@ fun () ->
    Id_map.find client_id db.id_map

  let lease_of_addr addr db = Util.find_some @@ fun () ->
    Addr_map.find addr db.addr_map

  let remove lease db =
    update_db
      (Id_map.remove lease.client_id db.id_map)
      (Addr_map.remove lease.addr db.addr_map)

  let replace lease db =
    (* First clear both maps *)
    let clr_map = match lease_of_addr lease.addr db with
      | Some l -> remove l db
      | None -> db
    in
    let clr_map = match lease_of_client_id lease.client_id clr_map with
      | Some l -> remove l db
      | None -> db
    in
    let clr_map = remove lease clr_map in
    update_db
      (Id_map.add lease.client_id lease clr_map.id_map)
      (Addr_map.add lease.addr lease clr_map.addr_map)

  let addr_allocated addr db =
    Util.true_if_some @@ lease_of_addr addr db

  let addr_available addr db ~now =
    match lease_of_addr addr db with
    | None -> true
    | Some lease -> expired lease ~now

(*
 * We try to use the last 4 bytes of the mac address as a hint for the ip
 * address, if that fails, we try a linear search.
 *)
  let get_usable_addr id db range ~now =
    match range with
    | None -> None
    | Some range ->
    let low_ip, high_ip = range in
    let low_32 = Ipaddr.V4.to_int32 low_ip in
    let high_32 = Ipaddr.V4.to_int32 high_ip in
    if (Int32.compare low_32 high_32) > 0 then
      invalid_arg "invalid range, must be (low * high)";
    let hint_ip =
      let v = match id with
        | Dhcp_wire.Id s -> Int32.of_int 1805 (* XXX who cares *)
        | Dhcp_wire.Hwaddr hw ->
          let s = String.sub (Macaddr.to_bytes hw) 2 4 in
          let b0 = Int32.shift_left (Char.code s.[3] |> Int32.of_int) 0 in
          let b1 = Int32.shift_left (Char.code s.[2] |> Int32.of_int) 8 in
          let b2 = Int32.shift_left (Char.code s.[1] |> Int32.of_int) 16 in
          let b3 = Int32.shift_left (Char.code s.[0] |> Int32.of_int) 24 in
          Int32.zero |> Int32.logor b0 |> Int32.logor b1 |>
          Int32.logor b2 |> Int32.logor b3
      in
      Int32.rem v (Int32.sub (Int32.succ high_32) low_32) |>
      Int32.abs |>
      Int32.add low_32 |>
      Ipaddr.V4.of_int32
    in
    let rec linear_loop off f =
      let ip = Ipaddr.V4.of_int32 (Int32.add low_32 off) in
      if f ip then
        Some ip
      else if off = high_32 then
        None
      else
        linear_loop (Int32.succ off) f
    in
    if not (addr_allocated hint_ip db) then
      Some hint_ip
    else match linear_loop Int32.zero (fun a -> not (addr_allocated a db)) with
      | Some ip -> Some ip
      | None -> linear_loop Int32.zero (fun a -> addr_available a db ~now)

end

module Input = struct
  open Config
  open Dhcp_wire

  let bad_packet fmt = Printf.ksprintf (fun s -> invalid_arg s) fmt

  type result =
    | Silence
    | Update of Lease.database
    | Reply of Dhcp_wire.pkt * Lease.database * (Ipaddr.V4.t * string) option
    | Warning of string
    | Error of string

  let host_of_mac config mac = Util.find_some @@
    fun () -> List.find (fun host -> host.hw_addr = mac) config.hosts

  let fixed_addr_of_mac config mac =
    match host_of_mac config mac with
    | Some host -> if host.hw_addr = mac then host.fixed_addr else None
    | None -> None

  let options_of_mac config mac =
    match host_of_mac config mac with
    | Some host -> host.options
    | None -> []

  let find_lease config client_id mac db ~now =
    match (fixed_addr_of_mac config mac) with
    | Some fixed_addr -> Some (Lease.make_fixed mac fixed_addr ~duration:config.default_lease_time ~now), true
    | None -> Lease.lease_of_client_id client_id db, false

  let good_address config mac addr db =
    match (fixed_addr_of_mac config mac) with
      (* If this is a fixed address, it's good if mac matches ip. *)
    | Some fixed_addr -> addr = fixed_addr
    | None -> (match config.range with
      | None -> false
      | Some range -> Util.addr_in_range addr range)

  let make_reply config reqpkt
      ~ciaddr ~yiaddr ~siaddr ~giaddr options =
    let op = BOOTREPLY in
    let htype = Ethernet_10mb in
    let hlen = 6 in
    let hops = 0 in
    let xid = reqpkt.xid in
    let secs = 0 in
    let flags = reqpkt.flags in
    let chaddr = reqpkt.chaddr in
    let sname = config.hostname in
    let file = "" in
    (* Build the frame header *)
    let dstport = if giaddr = Ipaddr.V4.unspecified then
        client_port
      else
        server_port
    in
    let srcport = server_port in
    let srcmac = config.mac_addr in
    let dstmac, dstip = match (find_message_type options) with
      | None -> failwith "make_reply: No msgtype in options"
      | Some m -> match m with
        | DHCPNAK -> if giaddr <> Ipaddr.V4.unspecified then
            (reqpkt.srcmac, giaddr)
          else
            (Macaddr.broadcast, Ipaddr.V4.broadcast)
        | DHCPOFFER | DHCPACK ->
          if giaddr <> Ipaddr.V4.unspecified then
            (reqpkt.srcmac, giaddr)
          else if ciaddr <> Ipaddr.V4.unspecified then
            (reqpkt.srcmac, ciaddr)
          else if flags = Unicast then
            (reqpkt.srcmac, yiaddr)
          else
            (Macaddr.broadcast, Ipaddr.V4.broadcast)
        | _ -> invalid_arg ("Can't send message type " ^ (msgtype_to_string m))
    in
    let srcip = config.ip_addr in
    { srcmac; dstmac; srcip; dstip; srcport; dstport;
      op; htype; hlen; hops; xid; secs; flags;
      ciaddr; yiaddr; siaddr; giaddr; chaddr; sname; file;
      options }

  let for_us config pkt =
    pkt.dstport = Dhcp_wire.server_port
    &&
    pkt.srcport = Dhcp_wire.client_port
    &&
    (pkt.dstmac = config.mac_addr ||
     pkt.dstmac = Macaddr.broadcast)
    &&
    (pkt.dstip = config.ip_addr ||
     pkt.dstip = Ipaddr.V4.broadcast)

  let valid_pkt pkt =
    if pkt.op <> BOOTREQUEST then
      false
    else if pkt.htype <> Ethernet_10mb then
      false
    else if pkt.hlen <> 6 then
      false
    else if pkt.hops <> 0 then
      false
    else
      true

  (* might be slow O(preqs * options) *)
  let replies_of_options options preqs =
    (* Sort parameter requests to guarantee ordering. *)
    let preqs =
      List.sort
        (fun a b -> compare (option_code_to_int a) (option_code_to_int b))
        preqs
    in
    let unassigned_options =
      List.filter (function Unassigned (_ ,_) -> true | _ -> false)
        options
    in
    (* matches multiple options *)
    let m fn fnr =
      match fn options with
      | [] -> None
      | l -> Some (fnr l)
    in
    (* matches the first single option *)
    let s fn fnr =
      match fn options with
      | Some x -> Some (fnr x)
      | None -> None
    in
    let consider = function
      | SUBNET_MASK -> s find_subnet_mask (fun x -> Subnet_mask x)
      | TIME_OFFSET -> s find_time_offset (fun x -> Time_offset x)
      | ROUTERS -> m collect_routers (fun x -> Routers x)
      | TIME_SERVERS -> m collect_time_servers (fun x -> Time_servers x)
      | NAME_SERVERS -> m collect_name_servers (fun x -> Name_servers x)
      | DNS_SERVERS -> m collect_dns_servers (fun x -> Dns_servers x)
      | LOG_SERVERS -> m collect_log_servers (fun x -> Log_servers x)
      | COOKIE_SERVERS -> m collect_cookie_servers (fun x -> Cookie_servers x)
      | LPR_SERVERS -> m collect_lpr_servers (fun x -> Lpr_servers x)
      | IMPRESS_SERVERS -> m collect_impress_servers (fun x -> Impress_servers x)
      | RSCLOCATION_SERVERS ->
        m collect_rsc_location_servers (fun x -> Rsclocation_servers x)
      | HOSTNAME -> s find_hostname (fun x -> Hostname x)
      | BOOTFILE_SIZE -> s find_bootfile_size (fun x -> Bootfile_size x)
      | MERIT_DUMPFILE -> s find_merit_dumpfile (fun x -> Merit_dumpfile x)
      | DOMAIN_NAME -> s find_domain_name (fun x -> Domain_name x)
      | SWAP_SERVER -> s find_swap_server (fun x -> Swap_server x)
      | ROOT_PATH -> s find_root_path (fun x -> Root_path x)
      | EXTENSION_PATH -> s find_extension_path (fun x -> Extension_path x)
      | IPFORWARDING -> s find_ipforwarding (fun x -> Ipforwarding x)
      | NLSR -> s find_nlsr (fun x -> Nlsr x)
      | POLICY_FILTERS -> m collect_policy_filters (fun x -> Policy_filters x)
      | MAX_DATAGRAM -> s find_max_datagram (fun x -> Max_datagram x)
      | DEFAULT_IP_TTL -> s find_default_ip_ttl (fun x -> Default_ip_ttl x)
      | PMTU_AGEING_TIMO -> s find_pmtu_ageing_timo (fun x -> Pmtu_ageing_timo x)
      | PMTU_PLATEAU_TABLE ->
        s find_pmtu_plateau_table (fun x -> Pmtu_plateau_table x)
      | INTERFACE_MTU -> s find_interface_mtu (fun x -> Interface_mtu x)
      | ALL_SUBNETS_LOCAL -> s find_all_subnets_local (fun x -> All_subnets_local x)
      | BROADCAST_ADDR -> s find_broadcast_addr (fun x -> Broadcast_addr x)
      | PERFORM_MASK_DISCOVERY ->
        s find_perform_mask_discovery (fun x -> Perform_router_disc x)
      | MASK_SUPPLIER -> s find_mask_supplier (fun x -> Mask_supplier x)
      | PERFORM_ROUTER_DISC ->
        s find_perform_router_disc (fun x -> Perform_router_disc x)
      | ROUTER_SOL_ADDR -> s find_router_sol_addr (fun x -> Router_sol_addr x)
      | STATIC_ROUTES -> m collect_static_routes (fun x -> Static_routes x)
      | TRAILER_ENCAPSULATION ->
        s find_trailer_encapsulation (fun x -> Trailer_encapsulation x)
      | ARP_CACHE_TIMO -> s find_arp_cache_timo (fun x -> Arp_cache_timo x)
      | ETHERNET_ENCAPSULATION ->
        s find_ethernet_encapsulation (fun x -> Ethernet_encapsulation x)
      | TCP_DEFAULT_TTL -> s find_tcp_default_ttl (fun x -> Tcp_default_ttl x)
      | TCP_KEEPALIVE_INTERVAL ->
        s find_tcp_keepalive_interval (fun x -> Tcp_keepalive_interval x)
      | TCP_KEEPALIVE_GARBAGE ->
        s find_tcp_keepalive_garbage (fun x -> Tcp_keepalive_garbage x)
      | NIS_DOMAIN -> s find_nis_domain (fun x -> Nis_domain x)
      | NIS_SERVERS -> m collect_nis_servers (fun x -> Nis_servers x)
      | NTP_SERVERS -> m collect_ntp_servers (fun x -> Ntp_servers x)
      | VENDOR_SPECIFIC -> s find_vendor_specific (fun x -> Vendor_specific x)
      | NETBIOS_NAME_SERVERS ->
        m collect_netbios_name_servers (fun x -> Netbios_name_servers x)
      | NETBIOS_DATAGRAM_DISTRIB_SERVERS ->
        m collect_netbios_datagram_distrib_servers
          (fun x -> Netbios_datagram_distrib_servers x)
      | NETBIOS_NODE -> s find_netbios_node (fun x -> Netbios_node x)
      | NETBIOS_SCOPE -> s find_netbios_scope (fun x -> Netbios_scope x)
      | XWINDOW_FONT_SERVERS ->
        m collect_xwindow_font_servers (fun x -> Xwindow_font_servers x)
      | XWINDOW_DISPLAY_MANAGERS ->
        m collect_xwindow_display_managers (fun x -> Xwindow_display_managers x)
      | REQUEST_IP -> None (* Previously included *)
      | IP_LEASE_TIME -> None   (* Previously included *)
      | OPTION_OVERLOAD -> s find_option_overload (fun x -> Option_overload x)
      | MESSAGE_TYPE -> None (* Senseless *)
      | SERVER_IDENTIFIER -> None (* Previously included *)
      | PARAMETER_REQUESTS -> None (* Senseless *)
      | MESSAGE -> s find_message (fun x -> Message x)
      | MAX_MESSAGE -> s find_max_message (fun x -> Max_message x)
      | RENEWAL_T1 -> None (* Previously included *)
      | REBINDING_T2 -> None (* Previously included *)
      | VENDOR_CLASS_ID -> s find_vendor_class_id (fun x -> Vendor_class_id x)
      | CLIENT_ID -> None (* Senseless *)
      | NETWARE_IP_DOMAIN ->
        s find_netware_ip_domain (fun x -> Netware_ip_domain x)
      | NETWARE_IP_OPTION ->
        s find_netware_ip_option (fun x -> Netware_ip_option x)
      | NIS_PLUS_DOMAIN -> s find_nis_plus_domain (fun x -> Nis_plus_domain x)
      | NIS_PLUS_SERVERS ->
        m collect_nis_plus_servers (fun x -> Nis_plus_servers x)
      | TFTP_SERVER_NAME -> s find_tftp_server_name (fun x -> Tftp_server_name x)
      | BOOTFILE_NAME -> s find_bootfile_name (fun x -> Bootfile_name x)
      | MOBILE_IP_HOME_AGENT ->
        m collect_mobile_ip_home_agent (fun x -> Mobile_ip_home_agent x)
      | SMTP_SERVERS -> m collect_smtp_servers (fun x -> Smtp_servers x)
      | POP3_SERVERS -> m collect_pop3_servers (fun x -> Pop3_servers x)
      | NNTP_SERVERS -> m collect_nntp_servers (fun x -> Nntp_servers x)
      | WWW_SERVERS -> m collect_www_servers (fun x -> Www_servers x)
      | FINGER_SERVERS -> m collect_finger_servers (fun x -> Finger_servers x)
      | IRC_SERVERS -> m collect_irc_servers (fun x -> Irc_servers x)
      | STREETTALK_SERVERS ->
        m collect_streettalk_servers (fun x -> Streettalk_servers x)
      | STREETTALK_DA ->
        m collect_streettalk_da (fun x -> Streettalk_da x)
      | USER_CLASS -> s find_user_class (fun x -> User_class x)
      | DIRECTORY_AGENT -> s find_directory_agent (fun x -> Directory_agent x)
      | SERVICE_SCOPE -> s find_service_scope (fun x -> Service_scope x)
      | RAPID_COMMIT -> s find_rapid_commit (fun _ -> Rapid_commit)
      | CLIENT_FQDN -> s find_client_fqdn (fun x -> Client_fqdn x)
      | RELAY_AGENT_INFORMATION ->
        s find_relay_agent_information (fun x -> Relay_agent_information x)
      | ISNS -> s find_isns (fun x -> Isns x)
      | NDS_SERVERS -> s find_nds_servers (fun x -> Nds_servers x)
      | NDS_TREE_NAME -> s find_nds_tree_name (fun x -> Nds_tree_name x)
      | NDS_CONTEXT -> s find_nds_context (fun x -> Nds_context x)
      | BCMCS_CONTROLLER_DOMAIN_NAME_LIST ->
        s find_bcmcs_controller_domain_name
          (fun x -> Bcmcs_controller_domain_name_list x)
      | BCMCS_CONTROLLER_IPV4_ADDR ->
        m collect_bcmcs_controller_ipv4_addrs
          (fun x -> Bcmcs_controller_ipv4_addrs x)
      | AUTHENTICATION -> s find_authentication (fun x -> Authentication x)
      | CLIENT_LAST_TRANSACTION_TIME ->
        s find_client_last_transaction_time
          (fun x -> Client_last_transaction_time x)
      | ASSOCIATED_IPS -> m collect_associated_ips (fun x -> Associated_ips x)
      | CLIENT_SYSTEM -> s find_client_system (fun x -> Client_system x)
      | CLIENT_NDI -> s find_client_ndi (fun x -> Client_ndi x)
      | LDAP -> s find_ldap (fun x -> Ldap x)
      | UUID_GUID -> s find_uuid_guid (fun x -> Uuid_guid x)
      | USER_AUTH -> s find_user_auth (fun x -> User_auth x)
      | GEOCONF_CIVIC -> s find_geoconf_civic (fun x -> Geoconf_civic x)
      | PCODE -> s find_pcode (fun x -> Pcode x)
      | TCODE -> s find_tcode (fun x -> Tcode x)
      | NETINFO_ADDRESS -> s find_netinfo_address (fun x -> Netinfo_address x)
      | NETINFO_TAG -> s find_netinfo_tag (fun x -> Netinfo_tag x)
      | URL -> s find_url (fun x -> Url x)
      | AUTO_CONFIG -> s find_auto_config (fun x -> Auto_config x)
      | NAME_SERVICE_SEARCH ->
        s find_name_service_search (fun x -> Name_service_search x)
      | SUBNET_SELECTION -> s find_subnet_selection (fun x -> Subnet_selection x)
      | DOMAIN_SEARCH -> s find_domain_search (fun x -> Domain_search x)
      | SIP_SERVERS -> s find_sip_servers (fun x -> Sip_servers x)
      | CLASSLESS_STATIC_ROUTE ->
        s find_classless_static_route (fun x -> Classless_static_route x)
      | CCC -> s find_ccc (fun x -> Ccc x)
      | GEOCONF -> s find_geoconf (fun x -> Geoconf x)
      | VI_VENDOR_CLASS -> s find_vi_vendor_class (fun x -> Vi_vendor_class x)
      | VI_VENDOR_INFO -> s find_vi_vendor_info (fun x -> Vi_vendor_info x)
      | PXE_128 -> s find_pxe_128 (fun x -> Pxe_128 x)
      | PXE_129 -> s find_pxe_129 (fun x -> Pxe_129 x)
      | PXE_130 -> s find_pxe_130 (fun x -> Pxe_130 x)
      | PXE_131 -> s find_pxe_131 (fun x -> Pxe_131 x)
      | PXE_132 -> s find_pxe_132 (fun x -> Pxe_132 x)
      | PXE_133 -> s find_pxe_133 (fun x -> Pxe_133 x)
      | PXE_134 -> s find_pxe_134 (fun x -> Pxe_134 x)
      | PXE_135 -> s find_pxe_135 (fun x -> Pxe_135 x)
      | PANA_AGENT -> s find_pana_agent (fun x -> Pana_agent x)
      | V4_LOST -> s find_v4_lost (fun x -> V4_lost x)
      | CAPWAP_AC_V4 -> s find_capwap_ac_v4 (fun x -> Capwap_ac_v4 x)
      | IPV4_ADDRESS_MOS -> s find_ipv4_address_mos (fun x -> Ipv4_address_mos x)
      | IPV4_FQDN_MOS -> s find_ipv4_fqdn_mos (fun x -> Ipv4_fqdn_mos x)
      | SIP_UA_DOMAINS -> s find_sip_ua_domains (fun x -> Sip_ua_domains x)
      | IPV4_ADDRESS_ANDSF ->
        s find_ipv4_address_andsf (fun x -> Ipv4_address_andsf x)
      | GEOLOCK -> s find_geolock (fun x -> Geolock x)
      | FORCENEW_NONCE_CAPABLE ->
        s find_forcenew_nonce_capable (fun x -> Forcenew_nonce_capable x)
      | RDNSS_SELECTION -> s find_rdnss_selection (fun x -> Rdnss_selection x)
      | MISC_150 -> s find_misc_150 (fun x -> Misc_150 x)
      | STATUS_CODE -> s find_status_code (fun x -> Status_code x)
      | ABSOLUTE_TIME -> s find_absolute_time (fun x -> Absolute_time x)
      | START_TIME_OF_STATE ->
        s find_start_time_of_state (fun x -> Start_time_of_state x)
      | QUERY_START_TIME -> s find_query_end_time (fun x -> Query_start_time x)
      | QUERY_END_TIME -> s find_query_end_time (fun x -> Query_end_time x)
      | DHCP_STATE -> s find_dhcp_state (fun x -> Dhcp_state x)
      | DATA_SOURCE -> s find_data_source (fun x -> Data_source x)
      | V4_PCP_SERVER -> s find_v4_pcp_server (fun x -> V4_pcp_server x)
      | V4_PORTPARAMS -> s find_v4_portparams (fun x -> V4_portparams x)
      | DHCP_CAPTIVE_PORTAL ->
        s find_dhcp_captive_portal (fun x -> Dhcp_captive_portal x)
      | ETHERBOOT_175 -> s find_etherboot_175 (fun x -> Etherboot_175 x)
      | IP_TELEFONE -> s find_ip_telefone (fun x -> Ip_telefone x)
      | ETHERBOOT_177 -> s find_etherboot_177 (fun x -> Etherboot_177 x)
      | PXE_LINUX -> s find_pxe_linux (fun x -> Pxe_linux x)
      | CONFIGURATION_FILE ->
        s find_configuration_file (fun x -> Configuration_file x)
      | PATH_PREFIX -> s find_path_prefix (fun x -> Path_prefix x)
      | REBOOT_TIME -> s find_reboot_time (fun x -> Reboot_time x)
      | OPTION_6RD -> s find_option_6rd (fun x -> Option_6rd x)
      | V4_ACCESS_DOMAIN -> s find_v4_access_domain (fun x -> V4_access_domain x)
      | SUBNET_ALLOCATION ->
        s find_subnet_allocation (fun x -> Subnet_allocation x)
      | VIRTUAL_SUBNET_SELECTION ->
        s find_virtual_subnet_selection (fun x -> Virtual_subnet_selection x)
      | WEB_PROXY_AUTO_DISC ->
        s find_web_proxy_auto_disc (fun x -> Web_proxy_auto_disc x)
      | PRIVATE_CLASSLESS_STATIC_ROUTE ->
        s find_private_classless_static_route (fun x -> Private_classless_static_route x)
      | UNASSIGNED_84  | UNASSIGNED_96  | UNASSIGNED_102 | UNASSIGNED_103
      | UNASSIGNED_104 | UNASSIGNED_105 | UNASSIGNED_106 | UNASSIGNED_107
      | UNASSIGNED_108 | UNASSIGNED_109 | UNASSIGNED_110 | UNASSIGNED_111
      | UNASSIGNED_115 | UNASSIGNED_126 | UNASSIGNED_127 | UNASSIGNED_143
      | UNASSIGNED_147 | UNASSIGNED_148 | UNASSIGNED_149 | UNASSIGNED_161
      | UNASSIGNED_162 | UNASSIGNED_163 | UNASSIGNED_164 | UNASSIGNED_165
      | UNASSIGNED_166 | UNASSIGNED_167 | UNASSIGNED_168 | UNASSIGNED_169
      | UNASSIGNED_170 | UNASSIGNED_171 | UNASSIGNED_172 | UNASSIGNED_173
      | UNASSIGNED_174 | UNASSIGNED_178 | UNASSIGNED_179 | UNASSIGNED_180
      | UNASSIGNED_181 | UNASSIGNED_182 | UNASSIGNED_183 | UNASSIGNED_184
      | UNASSIGNED_185 | UNASSIGNED_186 | UNASSIGNED_187 | UNASSIGNED_188
      | UNASSIGNED_189 | UNASSIGNED_190 | UNASSIGNED_191 | UNASSIGNED_192
      | UNASSIGNED_193 | UNASSIGNED_194 | UNASSIGNED_195 | UNASSIGNED_196
      | UNASSIGNED_197 | UNASSIGNED_198 | UNASSIGNED_199 | UNASSIGNED_200
      | UNASSIGNED_201 | UNASSIGNED_202 | UNASSIGNED_203 | UNASSIGNED_204
      | UNASSIGNED_205 | UNASSIGNED_206 | UNASSIGNED_207 | UNASSIGNED_214
      | UNASSIGNED_215 | UNASSIGNED_216 | UNASSIGNED_217 | UNASSIGNED_218
      | UNASSIGNED_219 | UNASSIGNED_222 | UNASSIGNED_223 | RESERVED_224
      | RESERVED_225   | RESERVED_226   | RESERVED_227   | RESERVED_228
      | RESERVED_229   | RESERVED_230   | RESERVED_231   | RESERVED_232
      | RESERVED_233   | RESERVED_234   | RESERVED_235   | RESERVED_236
      | RESERVED_237   | RESERVED_238   | RESERVED_239   | RESERVED_240
      | RESERVED_241   | RESERVED_242   | RESERVED_243   | RESERVED_244
      | RESERVED_245   | RESERVED_246   | RESERVED_247   | RESERVED_248
      | RESERVED_250   | RESERVED_251   | RESERVED_253   | RESERVED_254
      as code ->
        find_option
          (function Unassigned (c, s) as u when c = code -> Some u | _ -> None)
          unassigned_options
      | PAD | END -> None       (* Senseless *)
    in
    Util.filter_map consider preqs

  let collect_replies config mac preqs =
    match host_of_mac config mac with
    | Some host -> replies_of_options (host.options @ config.options) preqs
    | None -> replies_of_options config.options preqs

  let collect_replies_test = collect_replies

  let input_decline_release config db pkt now =
    let open Util in
    let msgtype = match find_message_type pkt.options with
      | Some msgtype -> msgtype_to_string msgtype
      | None -> failwith "Unexpected message type"
    in
    let ourip = config.ip_addr in
    let reqip = find_request_ip pkt.options in
    let sidip = find_server_identifier pkt.options in
    let client_id = client_id_of_pkt pkt in
    match sidip with
    | None -> bad_packet "%s without server identifier" msgtype
    | Some sidip ->
      if ourip <> sidip then
        Silence                 (* not for us *)
      else
        match reqip with
        | None -> bad_packet "%s without request ip" msgtype
        | Some reqip ->  (* check if the lease is actually his *)
          let lease, fixed_lease =
            find_lease config client_id pkt.chaddr db ~now in
          match lease with
          | None -> Silence (* lease is unowned, ignore *)
          | Some lease ->
            Update (
              if not fixed_lease then
                Lease.remove lease db
              else
                db)

  let input_decline = input_decline_release
  let input_release = input_decline_release

  let input_inform config db pkt =
    if pkt.ciaddr = Ipaddr.V4.unspecified then
      bad_packet "DHCPINFORM without ciaddr"
    else
      let ourip = config.ip_addr in
      let options =
        let open Util in
        cons (Message_type DHCPACK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs -> collect_replies config pkt.chaddr preqs
        | None -> []
      in
      let pkt = make_reply config pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db, None)

  let input_request config db pkt now =
    let client_id = client_id_of_pkt pkt in
    let lease, fixed_lease = find_lease config client_id pkt.chaddr db ~now in
    let ourip = config.ip_addr in
    let reqip = find_request_ip pkt.options in
    let sidip = find_server_identifier pkt.options in
    let nak ?msg () =
      let open Util in
      let options =
        cons (Message_type DHCPNAK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f msg (fun msg -> Message msg) @@
        cons_if_some_f (find_client_id pkt.options)
          (fun id -> Client_id id) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) []
      in
      let pkt = make_reply config pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:Ipaddr.V4.unspecified ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db, None)
    in
    let ack ?(renew=false) lease =
      let open Util in
      let lease = if renew then Lease.extend lease ~now else lease in
      let lease_time, t1, t2 =
        Lease.timeleft3 lease Config.t1_time_ratio Config.t2_time_ratio ~now
      in
      let options =
        cons (Message_type DHCPACK) @@
        cons (Ip_lease_time lease_time) @@
        cons (Renewal_t1 t1) @@
        cons (Rebinding_t2 t2) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs -> collect_replies config pkt.chaddr preqs
        | None -> []
      in
      let reply = make_reply config pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:lease.Lease.addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      let ipname = match find_hostname pkt.options with
        | None -> None
        | Some str -> Some (lease.Lease.addr, str)
      in
      if not fixed_lease then
        let () = assert (lease.Lease.client_id = client_id) in
        Reply (reply, Lease.replace lease db, ipname)
      else
        Reply (reply, db, ipname)
    in
    match sidip, reqip, lease with
    | Some sidip, Some reqip, _ -> (* DHCPREQUEST generated during SELECTING state *)
      if sidip <> ourip then (* is it for us ? *)
        Silence
      else if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        Warning "Bad DHCPREQUEST, ciaddr is not 0"
      else if not (good_address config pkt.chaddr reqip db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else
        (match lease with
         | Some lease ->
           if Lease.expired lease now &&
              not (Lease.addr_available reqip db ~now) then
             nak ~msg:"Lease has expired and address is taken" ()
           else if lease.Lease.addr <> reqip then
             nak ~msg:"Requested address is incorrect" ()
           else
             ack ~renew:true lease
         | None ->
           if not (Lease.addr_available reqip db ~now) then
             nak ~msg:"Requested address is not available" ()
           else
             ack (Lease.make client_id reqip
                    ~duration:config.default_lease_time ~now))
    | None, Some reqip, Some lease ->   (* DHCPREQUEST @ INIT-REBOOT state *)
      if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        bad_packet "Bad DHCPREQUEST, ciaddr is not 0"
      else if Lease.expired lease ~now &&
              not (Lease.addr_available reqip db ~now) then
        nak ~msg:"Lease has expired and address is taken" ()
        (* TODO check if it's in the correct network when giaddr <> 0 *)
      else if pkt.giaddr = Ipaddr.V4.unspecified &&
              not (good_address config pkt.chaddr reqip db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else if lease.Lease.addr <> reqip then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack lease
    | None, None, Some lease -> (* DHCPREQUEST @ RENEWING/REBINDING state *)
      if pkt.ciaddr = Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 renewal *)
        bad_packet "Bad DHCPREQUEST, ciaddr is not 0"
      else if Lease.expired lease ~now &&
              not (Lease.addr_available lease.Lease.addr db ~now) then
        nak ~msg:"Lease has expired and address is taken" ()
      else if lease.Lease.addr <> pkt.ciaddr then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack ~renew:true lease
    | _ -> Silence

  let discover_addr config lease db pkt now =
    let id = client_id_of_pkt pkt in
    match lease with
    (* Handle the case where we have a lease *)
    | Some lease ->
      if not (Lease.expired lease ~now) then
        Some lease.Lease.addr
        (* If the lease expired, the address might not be available *)
      else if (Lease.addr_available lease.Lease.addr db ~now) then
        Some lease.Lease.addr
      else
        Lease.get_usable_addr id db config.range ~now
    (* Handle the case where we have no lease *)
    | None -> match (find_request_ip pkt.options) with
      | Some req_addr ->
        if (good_address config pkt.chaddr req_addr db) &&
           (Lease.addr_available req_addr db ~now) then
          Some req_addr
        else
          Lease.get_usable_addr id db config.range ~now
      | None -> Lease.get_usable_addr id db config.range ~now

  let discover_lease_time config lease db pkt now =
    match (find_ip_lease_time pkt.options) with
    | Some ip_lease_time ->
      if Config.lease_time_good config ip_lease_time then
        ip_lease_time
      else
        config.default_lease_time
    | None -> match lease with
      | None -> config.default_lease_time
      | Some lease -> if Lease.expired lease ~now then
          config.default_lease_time
        else
          Lease.timeleft lease ~now

  let input_discover config db pkt now =
    (* RFC section 4.3.1 *)
    (* Figure out the ip address *)
    let id = client_id_of_pkt pkt in
    let lease, fixed_lease = find_lease config id pkt.chaddr db ~now in
    let ourip = config.ip_addr in
    let addr = discover_addr config lease db pkt now in
    (* Figure out the lease lease_time *)
    let lease_time = discover_lease_time config lease db pkt now in
    match addr with
    | None -> Warning "No ips left to offer"
    | Some addr ->
      let open Util in
      (* Start building the options *)
      let t1 = Int32.of_float
          (Config.t1_time_ratio *. (Int32.to_float lease_time)) in
      let t2 = Int32.of_float
          (Config.t2_time_ratio *. (Int32.to_float lease_time)) in
      let options =
        cons (Message_type DHCPOFFER) @@
        cons (Ip_lease_time lease_time) @@
        cons (Renewal_t1 t1) @@
        cons (Rebinding_t2 t2) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs ->
          collect_replies config pkt.chaddr preqs
        | None -> []
      in
      let pkt = make_reply config pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db, None)

  let input_pkt config db pkt time =
    try
      if not (for_us config pkt) then
        Silence
      else if valid_pkt pkt then
        match find_message_type pkt.options with
        | Some DHCPDISCOVER -> input_discover config db pkt time
        | Some DHCPREQUEST  -> input_request config db pkt time
        | Some DHCPDECLINE  -> input_decline config db pkt time
        | Some DHCPRELEASE  -> input_release config db pkt time
        | Some DHCPINFORM   -> input_inform config db pkt
        | None -> bad_packet "Malformed packet: no dhcp msgtype"
        | Some m -> Warning ("Unhandled msgtype " ^ (msgtype_to_string m))
      else
        bad_packet "Invalid packet"
    with
    | Invalid_argument e -> Error e
end
