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

(** A DHCP server is composed of two sub-modules: {! Config} and {! Input}.  The
    former deals with building a suitable configuration for using with the
    later.

   {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}}
*)

(** {2 DHCP Server Configuration } *)

module Config : sig

  type host = {
    hostname : string;
    options : Dhcp_wire.dhcp_option list;
    fixed_addr : Ipaddr.V4.t option;
    hw_addr : Macaddr.t;
  }
  (** {! host} config section entry. *)

  val host_of_sexp : Sexplib.Sexp.t -> host
  val sexp_of_host : host -> Sexplib.Sexp.t

  type t = {
    options : Dhcp_wire.dhcp_option list;
    hostname : string;
    default_lease_time : int32;
    max_lease_time : int32;
    ip_addr : Ipaddr.V4.t;
    mac_addr : Macaddr.t;
    network : Ipaddr.V4.Prefix.t;
    range : (Ipaddr.V4.t * Ipaddr.V4.t) option;
    hosts : host list;
  }
  (** Server configuration *)

  val t_of_sexp : Sexplib.Sexp.t -> t
  val sexp_of_t : t -> Sexplib.Sexp.t

  val parse : string -> (Ipaddr.V4.t * Macaddr.t) -> t
  (** [parse cf (addr * mac)] Creates a server configuration by parsing [cf] as an
      ISC dhcpd.conf file, currently only the options at [sample/dhcpd.conf] are
      supported. [addr] and [mac] are the prefix address and mac address to be
      used for building replies, it must match one subnet section in [cf].
      Raises Not_found if the (addr * mac) tuple does not match any network
      section. *)

  val make :
    ?hostname:string ->
    ?default_lease_time:int ->
    ?max_lease_time:int ->
    ?hosts:host list ->
    addr_tuple:Ipaddr.V4.t * Macaddr.t ->
    network:Ipaddr.V4.Prefix.t ->
    range:(Ipaddr.V4.t * Ipaddr.V4.t) option ->
    options:Dhcp_wire.dhcp_option list -> t

end

(** {2 DHCP Leases (bindings) } *)

module Lease : sig
  type t = {
    tm_start   : int32;
    tm_end     : int32;
    addr       : Ipaddr.V4.t;
    client_id  : Dhcp_wire.client_id;
  } [@@deriving sexp]

  val sexp_of_t : t -> Sexplib.Sexp.t
  val t_of_sexp : Sexplib.Sexp.t -> t

  val make_fixed : Macaddr.t -> Ipaddr.V4.t -> duration:int32 -> now:int32 -> t
  val timeleft : t -> now:int32 -> int32
  val timeleft_exn : t -> now:int32 -> int32
  val timeleft3 : t -> float -> float -> now:int32 -> int32 * int32 * int32
  val extend : t -> now:int32 -> t
  val expired : t -> now:int32 -> bool
  val to_string : t -> string

  type database

  val make_db : unit -> database
  val to_list : database -> t list
  val garbage_collect : database -> now:int32 -> database
  val remove : t -> database -> database
  val replace : t -> database -> database
  val lease_of_client_id : Dhcp_wire.client_id -> database -> t option
  val lease_of_addr : Ipaddr.V4.t -> database -> t option
  val addr_allocated : Ipaddr.V4.t -> database -> bool
  val addr_available : Ipaddr.V4.t -> database -> now:int32 -> bool
  val get_usable_addr :
    Dhcp_wire.client_id -> database ->
    (Ipaddr.V4.t * Ipaddr.V4.t) option -> now:int32 -> Ipaddr.V4.t option

end

(** {2 DHCP Input Packet Logic } *)

module Input : sig

  (** The logic for handling a DHCP input packet is pure, the module does not
      perform any IO, it only returns a possible reply packet or event to be
      logged.

      A typical server main loop would do its own IO for receiving a packet,
      then input with {! Input.input_pkt} and send out the resulting reply. *)

  type result =
    | Silence (** Input packet didn't belong to us, normal nop event.*)
    | Update of Lease.database (** Lease database update. *)
    | Reply of Dhcp_wire.pkt * Lease.database * (Ipaddr.V4.t * string) option
    (** Reply packet to be sent back and the corresponding lease database to be
        used in case the sent of the reply pkt is successfull *)
    | Warning of string (** An odd event, could be logged. *)
    | Error of string (** Input packet is invalid, or some other error ocurred. *)
    (** The result of [input_pkt]. *)

  val for_us : Config.t -> Dhcp_wire.pkt -> bool
  (** Check the packet headers, true if the packet is destined for us. *)

  val input_pkt : Config.t -> Lease.database -> Dhcp_wire.pkt -> int32 -> result
  (** [input_pkt config lease_db pkt time] Inputs packet [pkt], lease_db
      is the current lease database state, the resulting action should be
      performed by the caller, normally a [Reply] packet is returned and should be
      sent back. [time] is a int32 representing time as monotonic seconds. *)

  val collect_replies_test : Config.t -> Macaddr.t ->
    Dhcp_wire.option_code list -> Dhcp_wire.dhcp_option list
    (** Internal function exported for regression tests. Don't use this. *)

end
