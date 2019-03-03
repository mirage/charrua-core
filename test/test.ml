(*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2016 Gina Marie Maini <gina@beancode.io>
 * Copyright (c) 2016-2017 Mindy Preston
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

let () = Printexc.record_backtrace true

let printf = Printf.printf

let verbose = (Array.length Sys.argv) = 2 && Sys.argv.(1) = "-v"

let tty_out = Unix.isatty Unix.stdout && Unix.getenv "TERM" <> "dumb"
let colored_or_not cfmt fmt =
  if tty_out then (Printf.sprintf cfmt) else (Printf.sprintf fmt)
let red fmt    = colored_or_not ("\027[31m"^^fmt^^"\027[m") fmt
let green fmt  = colored_or_not ("\027[32m"^^fmt^^"\027[m") fmt
let yellow fmt = colored_or_not ("\027[33m"^^fmt^^"\027[m") fmt
let blue fmt   = colored_or_not ("\027[36m"^^fmt^^"\027[m") fmt

let ip_t = Ipaddr.V4.of_string_exn "192.168.1.1"
let ip2_t = Ipaddr.V4.of_string_exn "192.168.1.2"
let ip3_t = Ipaddr.V4.of_string_exn "192.168.1.3"
let ip4_t = Ipaddr.V4.of_string_exn "192.168.1.4"
let ip5_t = Ipaddr.V4.of_string_exn "192.168.1.5"
let ip55_t = Ipaddr.V4.of_string_exn "192.168.1.55"
let ip150_t = Ipaddr.V4.of_string_exn "192.168.1.150"
let mac_t = Macaddr.of_string_exn "aa:aa:aa:aa:aa:aa"
let mac2_t = Macaddr.of_string_exn "bb:bb:bb:bb:bb:bb"
let mask_t = Ipaddr.V4.of_string_exn "255.255.255.0"
let range_t = (Ipaddr.V4.of_string_exn "192.168.1.50",
               Ipaddr.V4.of_string_exn "192.168.1.100")

let assert_error x = assert (Rresult.R.is_error x)

open Dhcp_wire
open Dhcp_server

let now = Int32.one

let t_option_codes () =
  (* Make sure parameters 0-255 are there. *)
  for i = 0 to 255 do
    ignore (int_to_option_code_exn i)
  done

let t_csum () =
  let pkt = {
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = 0xabad1deal;
    chaddr = mac_t;
    srcport = client_port;
    dstport = server_port;
    srcmac = mac_t;
    dstmac = Macaddr.broadcast;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    op = BOOTREQUEST;
    secs = 0;
    flags = Broadcast;
    siaddr = Ipaddr.V4.any;
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    sname = "";
    file = "";
    options = [ Message_type DHCPREQUEST ]
  } in
  (* Corrupt every byte of the packet and assert that csum fails *)
  let buf = buf_of_pkt pkt in
  (* Skip ethernet + upper ip header *)
  for off = (14 + 12) to pred (Cstruct.len buf) do
    let evilbyte = Cstruct.get_uint8 buf off in
    (* Corrupt payload *)
    Cstruct.set_uint8 buf off (succ evilbyte);
    assert_error (pkt_of_buf buf (Cstruct.len buf));
    (* Put back *)
    Cstruct.set_uint8 buf off evilbyte;
  done

let t_long_lists () =
  let pkt = {
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = 0xabad1deal;
    chaddr = mac_t;
    srcport = client_port;
    dstport = server_port;
    srcmac = mac_t;
    dstmac = Macaddr.broadcast;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    op = BOOTREQUEST;
    secs = 0;
    flags = Broadcast;
    siaddr = Ipaddr.V4.any;
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    sname = "";
    file = "";
    options = [
      Message_type DHCPREQUEST;
      Dns_servers [
         Ipaddr.V4.of_string_exn "1.2.3.4";
         Ipaddr.V4.of_string_exn "2.3.4.5";
         Ipaddr.V4.of_string_exn "3.4.5.6";
         Ipaddr.V4.of_string_exn "4.5.6.7";
         Ipaddr.V4.of_string_exn "5.6.7.8";
         Ipaddr.V4.of_string_exn "6.7.8.9";
         Ipaddr.V4.of_string_exn "220.220.220.220";
      ]
    ]
  } in
  let serialized = buf_of_pkt pkt in
  match pkt_of_buf serialized (Cstruct.len serialized) with
  | Error e -> failwith e
  | Ok deserialized -> assert (pkt = deserialized)

let make_simple_config =
  Config.make
    ~hostname:"Duder DHCP server!"
    ~default_lease_time:(60 * 60 * 1)
    ~max_lease_time:(60 * 60 * 10)
    ~addr_tuple:(ip_t, mac_t)
    ~network:(Ipaddr.V4.Prefix.make 24 ip_t)
    ~range:(Some range_t)

(* Check if 3 lease timers are present and are what we expect. *)
let assert_timers options =
  let () = match find_ip_lease_time options with
    | None -> failwith "no Ip_lease_time found"
    | Some x -> assert (x = Int32.of_int 3600)
  in
  let () = match find_renewal_t1 options with
    | None -> failwith "no Renewal_t1 found"
    | Some x -> assert (x = Int32.of_int 1800)
  in
  match find_rebinding_t2 options with
  | None -> failwith "no Rebinding_t2 found"
  | Some x -> assert (x = Int32.of_int 2880)

let t_simple_config () =
  let config = make_simple_config ~hosts:[] ~options:[] in
  assert ((List.length config.Config.options) = 1);

  let config = make_simple_config ~hosts:[] ~options:[Routers [ip_t; ip2_t]; ] in
  assert ((List.length config.Config.options) = 2);
  match List.hd config.Config.options with
  | Subnet_mask _ -> ()
  | _ -> failwith "Subnet mask expected as first option"

let t_bad_options () =
  let ok = try
      ignore @@ make_simple_config ~hosts:[]
        ~options:[Renewal_t1 Int32.max_int];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "user cannot request renewal via options";
  let ok = try
      ignore @@ make_simple_config ~hosts:[]
        ~options:[Rebinding_t2 Int32.max_int];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "user cannot request rebinding via options";
  let ok = try
      ignore @@ make_simple_config ~hosts:[]
        ~options:[Ip_lease_time Int32.max_int];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "can't request ip lease time via options"

let t_bad_junk_padding_config () =
  let ok = try
      ignore @@ make_simple_config ~hosts:[] ~options:[
        Subnet_mask mask_t;
        End; (* Should not allow end in configuration *)
        Pad; (* Should not allow pad in configuration *)
        Client_id (Id "The dude");
      ];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "can't insert padding and random numbers via options"

let t_collect_replies () =
  let config = make_simple_config ~hosts:[]
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "wololo";
                Url "url";
                Pop3_servers [ip_t; ip2_t];
                Max_message 1200]
  in
  let requests = [DNS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
                  POP3_SERVERS; SUBNET_MASK; MAX_MESSAGE; RENEWAL_T1]
  in
  (* RENEWAL_T1 is ignored, so replies length should be - 1 *)
  let replies = Dhcp_server.Input.collect_replies_test config mac_t requests in
  assert ((List.length replies) = ((List.length requests) - 1));
  let () = match List.hd replies with
    | Subnet_mask _ -> ()
    | _ -> failwith "Subnet mask expected as first option"
  in
  assert ((List.length replies) = (List.length requests) - 1);
  let () = match List.hd @@ List.rev replies with
    | Url _ -> ()
    | _ -> failwith "Url expected to be last"
  in
  assert ((collect_routers replies) = [ip_t; ip2_t]);
  assert ((collect_dns_servers replies) = [ip_t]);
  assert ((find_domain_name replies) = Some "wololo");
  assert ((find_url replies) = Some "url");
  assert ((collect_pop3_servers replies) = [ip_t; ip2_t]);
  assert ((find_max_message replies) = Some 1200)

let t_host_options () =
  let open Dhcp_server.Config in
  let host = {
      hostname = "bubbles.trailer.park.boys";
      options = [
          Dns_servers [ip4_t];
          Routers [ip3_t];
          Dns_servers [];       (* Must be ignored *)
          Max_message 1400;
          Routers [ip5_t];
          Log_servers [ip5_t];
          Irc_servers [ip_t];   (* Won't ask must not be present *)
          Data_source 3;        (* Won't ask must not be present *)
        ];
      fixed_addr = None;
      hw_addr = mac_t
    }
  in
  let config = make_simple_config ~hosts:[host]
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "wololo";
                Url "url";
                Pop3_servers [ip_t; ip2_t];
                Max_message 1200];
  in
  let requests = [DNS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
                  POP3_SERVERS; SUBNET_MASK; MAX_MESSAGE; RENEWAL_T1; LOG_SERVERS]
  in
  let replies = Dhcp_server.Input.collect_replies_test config mac_t requests in
  assert ((collect_routers replies) = [ip3_t; ip5_t; ip_t; ip2_t]);
  assert ((collect_dns_servers replies) = [ip4_t; ip_t]);
  assert ((collect_log_servers replies) = [ip5_t]);
  assert ((collect_irc_servers replies) = []);
  assert ((find_data_source replies) = None);
  assert ((find_max_message replies) = (Some 1400))

let discover_pkt = {
    srcmac = mac2_t;
    dstmac = mac_t;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Unicast;
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = "";
    file = "";
    options = [
      Message_type DHCPDISCOVER;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ]
    ]
  }

let t_discover fixed =
  let open Dhcp_server.Config in
  let host = {
      hostname = "bubbles.trailer.park.boys";
      options = [];
      fixed_addr = Some ip150_t;
      hw_addr = mac_t
    }
  in
  let hosts = if fixed then [host] else [] in
  let config = make_simple_config ~hosts:hosts
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<DISCOVER>>") (pkt_to_string discover_pkt);
  match Input.input_pkt config (Lease.make_db ()) discover_pkt now with
  | Input.Reply (reply, db, _) ->
    assert (db = (Lease.make_db ()));
    assert (reply.srcmac = mac_t);
    assert (reply.dstmac = mac2_t);
    assert (reply.srcip = ip_t);
    assert (reply.dstip <> ip_t);
    assert (reply.dstip <> ip2_t);
    assert (reply.dstip <> Ipaddr.V4.any);
    assert (reply.srcport = server_port);
    assert (reply.dstport = client_port);
    assert (reply.op = BOOTREPLY);
    assert (reply.htype = Ethernet_10mb);
    assert (reply.hlen = 6);
    assert (reply.hops = 0);
    assert (reply.xid = Int32.of_int 0xabacabb);
    assert (reply.secs = 0);
    assert (reply.flags = Unicast);
    assert (reply.ciaddr = Ipaddr.V4.any);
    assert (reply.yiaddr <> Ipaddr.V4.any);
    assert (reply.yiaddr = reply.dstip);
    if fixed then
      assert (reply.yiaddr = ip150_t)
    else
      assert (Util.addr_in_range reply.yiaddr range_t);
    assert (reply.siaddr = ip_t);
    assert (reply.giaddr = Ipaddr.V4.any);
    assert (reply.sname = "Duder DHCP server!");
    assert (reply.file = "");
    (* 5 options are included regardless of parameter requests. *)
    assert ((List.length reply.options) = (5 + 6));
    let () = match List.hd reply.options with
      | Message_type x -> assert (x = DHCPOFFER);
      | _ -> failwith "First option is not Message_type"
    in
    assert_timers reply.options;
    (* Check if both router options are present, and the order matches *)
    let routers = collect_routers reply.options in
    assert ((List.length routers) = 2);
    assert ((List.hd routers) = ip_t);
    if verbose then
      printf "%s\n%s\n%!" (yellow "<<OFFER>>") (pkt_to_string reply);
  | _ -> failwith "No reply"

let t_discover_range () = t_discover false
let t_discover_fixed () = t_discover true

let t_discover_no_range () =
  let open Dhcp_server.Config in
  let config = Config.make
      ~hostname:"Duder DHCP server!"
      ~default_lease_time:(60 * 60 * 1)
      ~max_lease_time:(60 * 60 * 10)
      ~addr_tuple:(ip_t, mac_t)
      ~network:(Ipaddr.V4.Prefix.make 24 ip_t)
      ~hosts:[]
      ~range:None
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<DISCOVER>>") (pkt_to_string discover_pkt);
  match Input.input_pkt config (Lease.make_db ()) discover_pkt now with
  | Dhcp_server.Input.Warning s -> if s <> "No ips left to offer" then
      failwith "expected string `'No ips left to offer`'"
  | _ -> failwith "No reply"

let t_discover_no_range_fixed () =
  let open Dhcp_server.Config in
  let host = {
      hostname = "bubbles.trailer.park.boys";
      options = [];
      fixed_addr = Some ip150_t;
      hw_addr = mac_t
    }
  in
  let config = Config.make
      ~hostname:"Duder DHCP server!"
      ~default_lease_time:(60 * 60 * 1)
      ~max_lease_time:(60 * 60 * 10)
      ~addr_tuple:(ip_t, mac_t)
      ~network:(Ipaddr.V4.Prefix.make 24 ip_t)
      ~hosts:[host]
      ~range:None
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
    if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<DISCOVER>>") (pkt_to_string discover_pkt);
  match Input.input_pkt config (Lease.make_db ()) discover_pkt now with
  | Input.Reply (reply, db, _) ->
    assert (db = (Lease.make_db ()));
    assert (reply.srcmac = mac_t);
    assert (reply.dstmac = mac2_t);
    assert (reply.srcip = ip_t);
    assert (reply.dstip <> ip_t);
    assert (reply.dstip <> ip2_t);
    assert (reply.dstip <> Ipaddr.V4.any);
    assert (reply.srcport = server_port);
    assert (reply.dstport = client_port);
    assert (reply.op = BOOTREPLY);
    assert (reply.htype = Ethernet_10mb);
    assert (reply.hlen = 6);
    assert (reply.hops = 0);
    assert (reply.xid = Int32.of_int 0xabacabb);
    assert (reply.secs = 0);
    assert (reply.flags = Unicast);
    assert (reply.ciaddr = Ipaddr.V4.any);
    assert (reply.yiaddr <> Ipaddr.V4.any);
    assert (reply.yiaddr = reply.dstip);
    assert (reply.yiaddr = ip150_t);
    assert (reply.siaddr = ip_t);
    assert (reply.giaddr = Ipaddr.V4.any);
    assert (reply.sname = "Duder DHCP server!");
    assert (reply.file = "");
    (* 5 options are included regardless of parameter requests. *)
    assert ((List.length reply.options) = (5 + 6));
    let () = match List.hd reply.options with
      | Message_type x -> assert (x = DHCPOFFER);
      | _ -> failwith "First option is not Message_type"
    in
    assert_timers reply.options;
    (* Check if both router options are present, and the order matches *)
    let routers = collect_routers reply.options in
    assert ((List.length routers) = 2);
    assert ((List.hd routers) = ip_t);
    if verbose then
      printf "%s\n%s\n%!" (yellow "<<OFFER>>") (pkt_to_string reply);
  | _ -> failwith "No reply"

let t_bad_discover () =
  let config = make_simple_config ~hosts:[]
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "The Dude";
                Url "New shit has come to light, man.";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  let bad_discover = {
    srcmac = mac2_t;
    dstmac = Macaddr.of_string_exn "cc:cc:cc:cc:cc:cc";
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Unicast;
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = "";
    file = "";
    options = [
      Message_type DHCPDISCOVER;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ]
    ]
  }
  in
  match Input.input_pkt config (Lease.make_db ()) bad_discover now with
  | Input.Silence -> ()
  | _ -> failwith "This packet was not for us, should be Silence"

let request_nak_pkt = {
  srcmac = mac2_t;
  dstmac = mac_t;
  srcip = Ipaddr.V4.any;
  dstip = Ipaddr.V4.broadcast;
  srcport = client_port;
  dstport = server_port;
  op = BOOTREQUEST;
  htype = Ethernet_10mb;
  hlen = 6;
  hops = 0;
  xid = Int32.of_int 0xabacabb;
  secs = 0;
  flags = Broadcast;          (* Request a broadcast answer *)
  ciaddr = Ipaddr.V4.any;
  yiaddr = Ipaddr.V4.any;
  siaddr = Ipaddr.V4.any;
  giaddr = Ipaddr.V4.any;
  chaddr = mac_t;
  sname = "";
  file = "";
  options = [
    Message_type DHCPREQUEST;
    Client_id (Id "The Dude");
    Parameter_requests [
      DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
      POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
      NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
    ];
    Request_ip ip55_t;
    Server_identifier ip_t;
  ]
}


let t_request_fixed () =
  let open Dhcp_server.Config in
  let host = {
      hostname = "bubbles.trailer.park.boys";
      options = [];
      fixed_addr = Some ip150_t;
      hw_addr = mac_t
    }
  in
  let config = make_simple_config
      ~hosts:[host]
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  let request = {
    srcmac = mac2_t;
    dstmac = mac_t;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Broadcast;          (* Request a broadcast answer *)
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = "";
    file = "";
    options = [
      Message_type DHCPREQUEST;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ];
      Request_ip ip150_t;
      Server_identifier ip_t;
    ]
  }
  in
  if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<REQUEST>>") (pkt_to_string request);
  let db =
    match Input.input_pkt config (Lease.make_db ()) request now with
    | Input.Reply (reply, db, _) ->
      (* Fixed leases are mocked up, database should be unchanged *)
      assert (db = (Lease.make_db ()));
      let () =
        match Lease.lease_of_client_id (Id "W.Sobchak") db with
        | None -> () (* good, lease is not there. *)
        | Some l -> failwith "Found a fixed lease, bad juju."
      in
      assert (reply.srcmac = mac_t);
      assert (reply.dstmac = Macaddr.broadcast);
      assert (reply.srcip = ip_t);
      assert (reply.dstip = Ipaddr.V4.broadcast);
      assert (reply.srcport = server_port);
      assert (reply.dstport = client_port);
      assert (reply.op = BOOTREPLY);
      assert (reply.htype = Ethernet_10mb);
      assert (reply.hlen = 6);
      assert (reply.hops = 0);
      assert (reply.xid = Int32.of_int 0xabacabb);
      assert (reply.secs = 0);
      assert (reply.flags = Broadcast); (* Not required by RFC2131 section 4.1 *)
      assert (reply.ciaddr = Ipaddr.V4.any);
      assert (reply.yiaddr = ip150_t);
      assert (reply.siaddr = ip_t);
      assert (reply.giaddr = Ipaddr.V4.any);
      assert (reply.sname = "Duder DHCP server!");
      assert (reply.file = "");
      (* 5 options are included regardless of parameter requests. *)
      assert ((List.length reply.options) = (5 + 6));
      let () = match List.hd reply.options with
        | Message_type x -> assert (x = DHCPACK);
        | _ -> failwith "First option is not Message_type"
      in
      assert_timers reply.options;
      (* Server identifier must be there. *)
      assert (List.exists (function Server_identifier _ -> true | _ -> false)
          reply.options);
      (* Check if both router options are present, and the order matches *)
      let routers = collect_routers reply.options in
      assert ((List.length routers) = 2);
      assert ((List.hd routers) = ip_t);
      if verbose then
        printf "%s\n%s\n%!" (yellow "<<ACK>>") (pkt_to_string reply);
      db
    | _ -> failwith "No reply"
  in
  (* Build a second request from a different client, we should get a NAK. *)
  let request = request_nak_pkt in
  match Input.input_pkt config db request now with
  | Input.Reply (reply, odb, _) ->
    assert (db = odb);
    assert ((List.length reply.options) = 4);
    let () = match List.hd reply.options with
      | Message_type x -> assert (x = DHCPNAK);
      | _ -> failwith "First option is not Message_type"
    in
    if verbose then
      printf "%s\n%s\n%!" (yellow "<<NAK>>") (pkt_to_string reply);
  | _ -> failwith "No reply"

let t_request () =
  let config = make_simple_config ~hosts:[]
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  let request = {
    srcmac = mac2_t;
    dstmac = mac_t;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Broadcast;          (* Request a broadcast answer *)
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = "";
    file = "";
    options = [
      Message_type DHCPREQUEST;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ];
      Request_ip ip55_t;
      Server_identifier ip_t;
    ]
  }
  in
  if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<REQUEST>>") (pkt_to_string request);
  let db =
    match Input.input_pkt config (Lease.make_db ()) request now with
    | Input.Reply (reply, db, _) ->
      (* Check if our new lease is there *)
      assert (db <> (Lease.make_db ()));
      assert ((List.length (Lease.to_list db)) = 1);
      if verbose then
        printf "lease %s\n%!" (Lease.to_string (List.hd (Lease.to_list db)));
      let () =
        match Lease.lease_of_client_id (Id "W.Sobchak") db with
        | None -> failwith "Lease not found";
        | Some l ->
          let open Dhcp_server.Lease in
          assert (l.client_id = (Id "W.Sobchak"));
          assert (not (expired l now));
          assert (l.tm_start <= now);
          assert (l.tm_end >= now);
          assert ((Lease.timeleft l now) <= (Int32.of_int 3600));
          assert ((Lease.timeleft l now) >= (Int32.of_int 3599));
      in
      assert (reply.srcmac = mac_t);
      assert (reply.dstmac = Macaddr.broadcast);
      assert (reply.srcip = ip_t);
      assert (reply.dstip = Ipaddr.V4.broadcast);
      assert (reply.srcport = server_port);
      assert (reply.dstport = client_port);
      assert (reply.op = BOOTREPLY);
      assert (reply.htype = Ethernet_10mb);
      assert (reply.hlen = 6);
      assert (reply.hops = 0);
      assert (reply.xid = Int32.of_int 0xabacabb);
      assert (reply.secs = 0);
      assert (reply.flags = Broadcast); (* Not required by RFC2131 section 4.1 *)
      assert (reply.ciaddr = Ipaddr.V4.any);
      assert (reply.yiaddr <> Ipaddr.V4.any);
      assert (Util.addr_in_range reply.yiaddr range_t);
      assert (reply.siaddr = ip_t);
      assert (reply.giaddr = Ipaddr.V4.any);
      assert (reply.sname = "Duder DHCP server!");
      assert (reply.file = "");
      (* 5 options are included regardless of parameter requests. *)
      assert ((List.length reply.options) = (5 + 6));
      let () = match List.hd reply.options with
        | Message_type x -> assert (x = DHCPACK);
        | _ -> failwith "First option is not Message_type"
      in
      assert_timers reply.options;
      (* Server identifier must be there. *)
      assert (List.exists (function Server_identifier _ -> true | _ -> false)
          reply.options);
      (* Check if both router options are present, and the order matches *)
      let routers = collect_routers reply.options in
      assert ((List.length routers) = 2);
      assert ((List.hd routers) = ip_t);
      if verbose then
        printf "%s\n%s\n%!" (yellow "<<ACK>>") (pkt_to_string reply);
      db
    | _ -> failwith "No reply"
  in

  (* Build a second request from a different client, we should get a NAK. *)
  let request = request_nak_pkt in
  match Input.input_pkt config db request now with
  | Input.Reply (reply, odb, _) ->
    assert (db = odb);
    assert ((List.length reply.options) = 4);
    let () = match List.hd reply.options with
      | Message_type x -> assert (x = DHCPNAK);
      | _ -> failwith "First option is not Message_type"
    in
    if verbose then
      printf "%s\n%s\n%!" (yellow "<<NAK>>") (pkt_to_string reply);
  | _ -> failwith "No reply"

let t_request_no_range () =
  let open Dhcp_server.Config in
  let config = Config.make
      ~hostname:"Duder DHCP server!"
      ~default_lease_time:(60 * 60 * 1)
      ~max_lease_time:(60 * 60 * 10)
      ~addr_tuple:(ip_t, mac_t)
      ~network:(Ipaddr.V4.Prefix.make 24 ip_t)
      ~hosts:[]
      ~range:None
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  let request = {
    srcmac = mac2_t;
    dstmac = mac_t;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Broadcast;          (* Request a broadcast answer *)
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = "";
    file = "";
    options = [
      Message_type DHCPREQUEST;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ];
      Request_ip ip55_t;
      Server_identifier ip_t;
    ]
  }
  in
  if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<REQUEST>>") (pkt_to_string request);
  match Input.input_pkt config (Lease.make_db ()) request now with
  | Dhcp_server.Input.Reply (reply, db, _) ->
    assert (db = (Lease.make_db ()));
    assert ((List.length reply.options) = 4);
    let () = match List.hd reply.options with
      | Message_type x -> assert (x = DHCPNAK);
      | _ -> failwith "First option is not Message_type"
    in
    let () = match find_message reply.options with
      | None -> failwith "No nice message for NAK"
      | Some m -> assert (m = "Requested address is not in subnet range")
    in ()
  | _ -> failwith "Unexpected reply"

let t_request_no_range_fixed () =
  let open Dhcp_server.Config in
  let host = {
      hostname = "bubbles.trailer.park.boys";
      options = [];
      fixed_addr = Some ip150_t;
      hw_addr = mac_t
    }
  in
  let config = Config.make
      ~hostname:"Duder DHCP server!"
      ~default_lease_time:(60 * 60 * 1)
      ~max_lease_time:(60 * 60 * 10)
      ~addr_tuple:(ip_t, mac_t)
      ~network:(Ipaddr.V4.Prefix.make 24 ip_t)
      ~hosts:[host]
      ~range:None
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  let request = {
    srcmac = mac2_t;
    dstmac = mac_t;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Broadcast;          (* Request a broadcast answer *)
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = "";
    file = "";
    options = [
      Message_type DHCPREQUEST;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ];
      Request_ip ip150_t;
      Server_identifier ip_t;
    ]
  }
  in
  if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<REQUEST>>") (pkt_to_string request);
  match Input.input_pkt config (Lease.make_db ()) request now with
  | Input.Reply (reply, db, _) ->
    (* Check if our new lease is there *)
    assert (db = (Lease.make_db ()));
    let () =
      match Lease.lease_of_client_id (Id "W.Sobchak") db with
      | None -> () (* good, lease is not there. *)
      | Some l -> failwith "Found a fixed lease, bad juju."
    in
    assert (reply.srcmac = mac_t);
    assert (reply.dstmac = Macaddr.broadcast);
    assert (reply.srcip = ip_t);
    assert (reply.dstip = Ipaddr.V4.broadcast);
    assert (reply.srcport = server_port);
    assert (reply.dstport = client_port);
    assert (reply.op = BOOTREPLY);
    assert (reply.htype = Ethernet_10mb);
    assert (reply.hlen = 6);
    assert (reply.hops = 0);
    assert (reply.xid = Int32.of_int 0xabacabb);
    assert (reply.secs = 0);
    assert (reply.flags = Broadcast); (* Not required by RFC2131 section 4.1 *)
    assert (reply.ciaddr = Ipaddr.V4.any);
    assert (reply.yiaddr = ip150_t);
    assert (not (Util.addr_in_range reply.yiaddr range_t));
    assert (reply.siaddr = ip_t);
    assert (reply.giaddr = Ipaddr.V4.any);
    assert (reply.sname = "Duder DHCP server!");
    assert (reply.file = "");
    (* 5 options are included regardless of parameter requests. *)
    assert ((List.length reply.options) = (5 + 6));
    let () = match List.hd reply.options with
      | Message_type x -> assert (x = DHCPACK);
      | _ -> failwith "First option is not Message_type"
    in
    assert_timers reply.options;
    (* Server identifier must be there. *)
    assert (List.exists (function Server_identifier _ -> true | _ -> false)
        reply.options);
    (* Check if both router options are present, and the order matches *)
    let routers = collect_routers reply.options in
    assert ((List.length routers) = 2);
    assert ((List.hd routers) = ip_t);
    if verbose then
      printf "%s\n%s\n%!" (yellow "<<ACK>>") (pkt_to_string reply)
  | _ -> failwith "No reply"

let run_test test =
  let f = fst test in
  let name = snd test in
  printf "%s %-40s%!" (blue "%s" "Test") (yellow "%s" name);
  let () = try f () with
      exn -> printf "%s\n%!" (red "failed");
      raise exn
  in
  printf "%s\n%!" (green "ok")

let all_tests = [
  (t_option_codes, "option codes");
  (t_csum, "checksum");
  (t_long_lists, "long options lists");
  (Pcap.t_pcap, "pcap");
  (t_simple_config, "simple config");
  (t_bad_options, "renewal_t in opts");
  (t_bad_junk_padding_config, "padding in opts");
  (t_collect_replies, "collect replies");
  (t_host_options, "host options");
  (t_discover_range, "discover->offer");
  (t_discover_fixed, "discover->offer fixed");
  (t_discover_no_range, "discover->offer no range");
  (t_discover_no_range_fixed, "discover->offer no range fixed");
  (t_bad_discover, "wrong mac address");
  (t_request, "request->ack/nak");
  (t_request_fixed, "request->ack/nak fixed");
  (t_request_no_range, "request->ack/nak no range");
  (t_request_no_range_fixed, "request->ack/nak no range fixed");
]

let _ =
  List.iter run_test all_tests;
