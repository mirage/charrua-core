let cstruct = Alcotest.of_pp Cstruct.hexdump_pp

let msgtype =
  let module M = struct
    type t = Dhcp_wire.msgtype
    let pp fmt m = Format.fprintf fmt "%s" (Dhcp_wire.msgtype_to_string m)
    let equal p q = (compare p q) = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

module Defaults = struct
  let client_mac = Macaddr.of_string_exn "00:16:3e:ba:eb:ba"
  let server_mac = Macaddr.of_string_exn "00:16:3e:00:00:00"
  let server_ip = Ipaddr.V4.of_string_exn "192.168.1.1"
  let server_network = Ipaddr.V4.Prefix.make 24 server_ip
  let range = Some (Ipaddr.V4.of_string_exn "192.168.1.15", Ipaddr.V4.of_string_exn "192.168.1.65")
  let options = []
  let config = Dhcp_server.Config.make
    ?hostname:None ?default_lease_time:None
    ?max_lease_time:None ?hosts:None
    ~addr_tuple:(server_ip, server_mac)
    ~network:server_network ~range ~options
  let empty_db = Dhcp_server.Lease.make_db ()
end

let random_buffer () =
  let sz = Cstruct.BE.get_uint16 (Mirage_random_test.generate 2) 0 in
  Mirage_random_test.generate sz

let rec no_result t n () =
  if n <= 0 then ()
  else begin
  let buf = random_buffer () in
  (* TODO: it would be better to randomize a valid DHCP message; currently
   * we're fuzz testing the Dhcp_wire parser's ability to handle random garbage *)
  let res = Dhcp_client.input t buf in
  Alcotest.(check bool) "no action" true (res = `Noop);
  no_result t (n - 1) ()
  end
;;

let parseable buf =
  Alcotest.(check bool) "buffer we constructed is valid dhcp" true (Dhcp_wire.is_dhcp buf (Cstruct.len buf))

let random_xid () = Cstruct.BE.get_uint32 (Mirage_random_test.generate 4) 0

let start_makes_dhcp () =
  let (_s, pkt) = Dhcp_client.create (random_xid ()) Defaults.client_mac in
  (* for now, any positive result is fine *)
  parseable (Dhcp_wire.buf_of_pkt pkt)

let client_to_selecting () =
  let open Defaults in
  let (s, pkt) = Dhcp_client.create (random_xid ()) client_mac in
  let buf = Dhcp_wire.buf_of_pkt pkt in
  let answer = Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
  Alcotest.(check (result pass reject)) "input succeeds" answer answer;
  (s, Rresult.R.get_ok answer)

let assert_reply p =
  let open Dhcp_server.Input in
  match p with
  | Warning s | Error s -> Alcotest.fail s
  | Silence -> Alcotest.fail "Silence from the server in response to a request"
  | Update _db -> Alcotest.fail "database update but no reply -- in our context this is likely a bug"
  | Reply (pkt, db, _) -> (pkt, db)

let server_accepts_start_packet () =
  let open Defaults in
  let (_, dhcpdiscover) = client_to_selecting () in
  ignore @@ assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0l

let server_gives_dhcpoffer () =
  let open Defaults in
  let open Dhcp_wire in
  let (_, dhcpdiscover) = client_to_selecting () in
  let (pkt, _db) = assert_reply @@
    Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0l in
  Alcotest.(check (option msgtype)) "initial message merited a DHCPOFFER"
    (Some DHCPOFFER) (find_message_type pkt.options)

let client_rejects_wrong_xid () =
  let open Defaults in
  let (s, answer) = client_to_selecting () in
  let (pkt, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db answer 0l in
  let pkt = Dhcp_wire.({pkt with xid = Int32.add pkt.xid 1l}) in
  Alcotest.(check bool) "don't respond to dhcpoffer with non-matching xid"
    true (`Noop = Dhcp_client.input s @@ Dhcp_wire.buf_of_pkt pkt)

let client_asks_dhcprequest () =
  let open Dhcp_wire in
  let open Defaults in
  let (s, answer) = client_to_selecting () in
  let (pkt, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db answer 0l in
  match find_message_type pkt.options with
  | Some DHCPOFFER -> begin
    match Dhcp_client.input s (Dhcp_wire.buf_of_pkt pkt) with
    | `Noop -> Alcotest.fail "response to DHCPOFFER was silence"
    | `New_lease _ -> Alcotest.fail "thought a DHCPOFFER was a lease???"
    | `Response (s, pkt) ->
      let buf = Dhcp_wire.buf_of_pkt pkt in
      parseable buf;
      let dhcprequest = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
      Alcotest.(check (option msgtype)) "responded to DHCPOFFER with DHCPREQUEST"
        (Some DHCPREQUEST) (find_message_type dhcprequest.options)
  end
  | _ -> Alcotest.fail "couldn't get a valid DHCPOFFER to attempt to send DHCPREQUEST in response to"

let server_gives_dhcpack () =
  let open Dhcp_wire in
  let open Defaults in
  let (s, dhcpdiscover) = client_to_selecting () in
  let (dhcpoffer, db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0l in
  match Dhcp_client.input s (Dhcp_wire.buf_of_pkt dhcpoffer) with
  | `Noop -> Alcotest.fail "couldn't get client to respond to DHCPOFFER"
  | `New_lease _-> Alcotest.fail "thought a DHCPOFFER was a lease"
  | `Response (s, pkt) ->
    let buf = Dhcp_wire.buf_of_pkt pkt in
    let dhcprequest = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
    let (dhcpack, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config db dhcprequest 0l in
      Alcotest.(check (option msgtype)) "got a DHCPACK in response to DHCPREQUEST"
        (Some DHCPACK) (find_message_type dhcpack.options)

let client_returns_lease () =
  let open Dhcp_wire in
  let open Defaults in
  let (s, dhcpdiscover) = client_to_selecting () in
  let (dhcpoffer, db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0l in
  match Dhcp_client.input s (Dhcp_wire.buf_of_pkt dhcpoffer) with
  | `Noop | `New_lease _ -> Alcotest.fail "incorrect response to DHCPOFFER"
  | `Response (s, pkt) ->
    let buf = Dhcp_wire.buf_of_pkt pkt in
    let dhcprequest = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
    let (dhcpack, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config db dhcprequest 0l in
    Alcotest.(check (option msgtype)) "got a DHCPACK in response to DHCPREQUEST"
      (Some DHCPACK) (find_message_type dhcpack.options);
    match Dhcp_client.input s (Dhcp_wire.buf_of_pkt dhcpack) with
    | `Response _ ->
Alcotest.fail "client wanted to send more packets after receiving DHCPACK"
    | `Noop -> Alcotest.fail "client disregarded its lease"
    | `New_lease (s, l) ->
       Alcotest.(check (option pass)) "lease is held" (Some dhcpack) (Dhcp_client.lease s)

let random_init n =
  let (s, _) = Dhcp_client.create (random_xid ()) Defaults.client_mac in
  "random buffer entry to INIT client", `Quick, (no_result s n)

let random_selecting n =
  let (s, _) = client_to_selecting () in
  "random buffer entry to SELECTING client", `Quick, (no_result s n)

let random_requesting n =
  let open Defaults in
  let (s, dhcpdiscover) = client_to_selecting () in
  let (pkt, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0l in
  match Dhcp_client.input s (Dhcp_wire.buf_of_pkt pkt) with
  | `Noop | `New_lease _ -> Alcotest.fail "couldn't enter REQUESTING properly"
| `Response (s, dhcprequest) ->
  "random buffer entry to REQUESTING client", `Quick, (no_result s n)

let random_bound n =
  let open Defaults in
  let (s, dhcpdiscover) = client_to_selecting () in
  let (pkt, db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0l in
  match Dhcp_client.input s (Dhcp_wire.buf_of_pkt pkt) with
  | `Noop | `New_lease _ -> Alcotest.fail "couldn't enter REQUESTING properly"
  | `Response (s, dhcprequest) ->
    let buf = Dhcp_wire.buf_of_pkt dhcprequest in
    let dhcprequest = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
    let (dhcpack, db) = assert_reply @@ Dhcp_server.Input.input_pkt config db dhcprequest 0l in
    match Dhcp_client.input s (Dhcp_wire.buf_of_pkt dhcpack) with
    | `Noop | `Response _ -> Alcotest.fail "client did not recognize DHCPACK as
a new lease"
    | `New_lease (s, response) ->
      "random buffer entry to BOUND client", `Quick, (no_result s n)

let () =
  Mirage_random_test.initialize () ;
  let nfuzz = 100 in
  Alcotest.run "client tests" [
    (* these tests will programmatically put [Dhcp_client.t] into a particular
     * state, then throw random input at it the specified number of times. *)
    "random input tests", [
        random_init nfuzz;
        random_selecting nfuzz;
        random_requesting nfuzz;
        random_bound nfuzz;
    ];
    "state progression", [
       "initializing state machine generates a dhcp packet", `Quick, start_makes_dhcp;
       "dhcp server accepts start packet", `Quick, server_accepts_start_packet;
       "dhcp client doesn't accept DHCPOFFER with wrong xid", `Quick, client_rejects_wrong_xid;
       "dhcp server offers a lease in response to start packet", `Quick, server_gives_dhcpoffer;
       "dhcp client sends a dhcp packet in response to DHCPOFFER", `Quick, client_asks_dhcprequest;
       "dhcp server sends a DHCPACK in response to client DHCPREQUEST", `Quick, server_gives_dhcpack;
       "dhcp client returns lease after receiving DHCPACK", `Quick, client_returns_lease;
      ]
    ]
