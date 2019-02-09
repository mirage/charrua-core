open Lwt.Infix

(* additional tests for time- and network-dependent code *)

module No_random = struct
  type buffer = Cstruct.t
  type g
  let generate ?g n = Cstruct.create n
end

module No_time = struct
  type 'a io = 'a Lwt.t
  let sleep_ns n = Format.printf "Ignoring request to wait %f seconds\n" @@ Duration.to_f n;
    Lwt_main.yield ()
end

module No_net = struct
  type error = Mirage_net.Net.error
  let pp_error = Mirage_net.Net.pp_error
  type stats = Mirage_net.stats
  type 'a io = 'a Lwt.t
  type macaddr = Macaddr.t
  type buffer = Cstruct.t
  type t = { mac : Macaddr.t; mutable packets : Cstruct.t list }
  let disconnect _ = Lwt.return_unit
  let write t ?size fillf =
    let size = 14 + match size with None -> 1500 | Some s -> s in
    let buf = Cstruct.create size in
    let l = 14 + fillf buf in
    assert (l <= size);
    let b = Cstruct.sub buf 0 l in
    t.packets <- t.packets @ [b];
    Lwt.return_ok ()
  let listen _ _ = Lwt.return_ok ()
  let mac t = t.mac
  let mtu t = 1500
  let reset_stats_counters _ = ()
  let get_stats_counters _ = {
    Mirage_net.rx_bytes = 0L;
    tx_bytes = 0L;
    rx_pkts = 0l;
    tx_pkts = 0l;
  }
  let connect ~mac () = { packets = []; mac }
  let get_packets t = t.packets
end

let keep_trying () =
  Lwt_main.run @@ (
    let module Client = Dhcp_client_lwt.Make(No_random)(No_time)(No_net) in
    let net = No_net.connect ~mac:(Macaddr.of_string_exn "c0:ff:ee:c0:ff:ee") () in
    let test =
      Client.connect net >>= Lwt_stream.get >|= function
      | Some _ -> Alcotest.fail "got a lease from a nonfunctioning network somehow"
      | None -> ()
    in
    Lwt.pick [
      test;
      Lwt_main.yield () >>= function () ->
      (Alcotest.(check bool) "sent >1 packet" true (List.length (No_net.get_packets net) > 1); Lwt.return_unit)
    ]
  )

let () =
  Alcotest.run "lwt client tests" [
    "timeouts", [
       "more than one dhcpdiscover is sent", `Quick, keep_trying;
    ]
  ]
