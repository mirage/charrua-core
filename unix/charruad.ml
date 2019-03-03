(*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

let filter_map f l = List.rev @@
  List.fold_left (fun a v -> match f v with Some v' -> v'::a | None -> a) [] l

let level_of_string = function
  | "warning" -> Lwt_log.Warning
  | "notice" -> Lwt_log.Notice
  | "debug" -> Lwt_log.Debug
  | _ -> invalid_arg "Unknown verbosity level"

(* Drop privileges and chroot to _charruad home *)
let go_safe () =
  let (pw, gr) = try
      (Unix.getpwnam "_charruad", Unix.getgrnam "_charruad")
    with _  ->
      failwith "No user and/or group _charruad found, please create them."
  in
  Unix.chroot pw.Unix.pw_dir;
  Unix.chdir "/";
  (* Unix.setproctitle "charruad"; XXX implement me *)
  let ogid = Unix.getgid () in
  let oegid = Unix.getegid () in
  let ouid = Unix.getuid () in
  let oeuid = Unix.geteuid () in
  Unix.setgroups (Array.of_list [pw.Unix.pw_gid]);
  Unix.setgid pw.Unix.pw_gid;
  Unix.setuid pw.Unix.pw_uid;
  if ogid = pw.Unix.pw_gid ||
     oegid = pw.Unix.pw_gid ||
     ouid = pw.Unix.pw_uid ||
     oeuid = pw.Unix.pw_uid then
    failwith "Unexpected uid or gid after dropping privileges";
  (* Make sure we cant restore the old gid and uid *)
  let canrestore = try
      Unix.setuid ouid;
      Unix.setuid oeuid;
      Unix.setgid ogid;
      Unix.setgid oegid;
      true
    with _ -> false in
  if canrestore then
    failwith "Was able to restore UID, setuid is broken"

let read_file f =
  let ic = open_in f in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.to_string buf

let go_daemon () =
  Lwt_daemon.daemonize ~syslog:false ()

let init_log vlevel daemon =
  Lwt_log_core.Section.(set_level main vlevel);
  Lwt_log.default := if daemon then
      Lwt_log.syslog
        ~template:"$(date) $(level) $(name)[$(pid)]: $(message)"
        ~facility:`Daemon
        ~paths:["/dev/log"; "/var/run/log"; "/var/run/syslog"]
        ()
    else
      Lwt_log.channel
        ~template:"$(date) $(level): $(message)"
        ~close_mode:`Keep
        ~channel:Lwt_io.stdout
        ()

let rec input config db link =
  let open Dhcp_server.Input in
  let open Lwt in

  Lwt_rawlink.read_packet link
  >>= fun buf ->
  let t = match Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) with
    | Error e -> Lwt_log.error e
      >>= fun () ->
      return db
    | Ok pkt ->
      Lwt_log.debug_f "Received packet: %s" (Dhcp_wire.pkt_to_string pkt)
      >>= fun () ->
      let now = Mtime_clock.elapsed () |> Mtime.Span.to_s |> Int32.of_float in
      match (input_pkt config db pkt now) with
      | Silence -> return db
      | Update db -> return db
      | Reply (reply, db, _) ->
        Lwt_rawlink.send_packet link (Dhcp_wire.buf_of_pkt reply)
        >>= fun () ->
        Lwt_log.debug_f "Sent reply packet: %s" (Dhcp_wire.pkt_to_string reply)
        >>= fun () ->
        return db
      | Warning w -> Lwt_log.warning w
        >>= fun () ->
        return db
      | Error e -> Lwt_log.error e
        >>= fun () ->
        return db
  in
  t >>= fun db -> input config db link

let ifname_of_address ip_addr interfaces =
  let ifnet =
    List.find (function name, (ip_addrx, _) -> ip_addr = ip_addrx) interfaces
  in
  match ifnet with name, (_, _) -> name

let charruad configfile verbosity daemonize =
  let open Dhcp_server.Config in
  let open Dhcp_server.Lease in
  let open Lwt in

  init_log (level_of_string verbosity) daemonize;
  let interfaces = Tuntap.getifaddrs_v4 () in
  let addresses = List.map
      (function name, (addr, _) -> (addr, Tuntap.get_macaddr name))
      interfaces
  in
  let configtxt = read_file configfile in
  (* let config = parse configtxt addresses in *)
  let db = make_db () in
  if daemonize then
    go_daemon ();
  Lwt_log.ign_notice "Charrua DHCPD starting";
  (* Filter out the addresses which have networks assigned *)
  let threads = filter_map
      (fun addr_tuple ->
         let addr = fst addr_tuple in
         let s = Ipaddr.V4.to_string addr in
         let config = try Some (parse configtxt addr_tuple) with Not_found -> None in
         match config with
         | Some config ->
           Lwt_log.ign_notice_f "Found network for %s" s;
           (* Get a rawlink on the interface *)
           let ifname = ifname_of_address addr interfaces in
           let link = Lwt_rawlink.(open_link ~filter:(dhcp_server_filter ()) ifname) in
           (* Create a thread *)
           Some (input config db link)
         | None ->
           let () = Lwt_log.ign_debug_f "No network found for %s" s in
           None)
      addresses
  in
  if List.length threads = 0 then
    failwith "Could not match any interface address with any network section.";
  go_safe ();
  Lwt_main.run (Lwt.pick threads >>= fun _ ->
                Lwt_log.notice "Charrua DHCPD exiting")

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let configfile = Arg.(value & opt string "/etc/dhcpd.conf" & info ["c" ; "config"]
                          ~doc:"Configuration file path") in
  let verbosity = Arg.(value & opt string "notice" & info ["v" ; "verbosity"]
                         ~doc:"Log verbosity, warning|notice|debug") in
  let daemonize = Arg.(value & flag & info ["D" ; "daemon"]
                         ~doc:"Daemonize") in
  (* let color = *)
  (*   let when_enum = [ "always", `Always; "never", `Never; "auto", `Auto ] in *)
  (*   let doc = Arg.info ~docv:"WHEN" *)
  (*       ~doc:(Printf.sprintf "Colorize the output. $(docv) must be %s." *)
  (*               (Arg.doc_alts_enum when_enum)) ["color"] in *)
  (*   Arg.(value & opt (enum when_enum) `Auto & doc) in *)
  Term.(pure charruad $ configfile $ verbosity $ daemonize),
  Term.info "charruad" ~version:"0.1" ~doc:"Charrua DHCPD"
let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
