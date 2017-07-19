open Lwt.Infix

let src =
  let src = Logs.Src.create "mux" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module DontCareAboutStats = struct
  let get_stats_counters _ = Mirage_net.Stats.create ()
  let reset_stats_counters _ = ()
end

module ObviouslyCommon = struct
  type page_aligned_buffer = Io_page.t

  type buffer = Cstruct.t

  type error = [`Unknown of string | Mirage_net.error]

  let pp_error ppf = function
    | #Mirage_net.error as e -> Mirage_net.pp_error ppf e
    | `Unknown s -> Fmt.string ppf s

  type macaddr = Macaddr.t

  type 'a io = 'a Lwt.t

  type id = unit
end

module Make(Netif: Mirage_net_lwt.S) = struct
  include DontCareAboutStats
  include ObviouslyCommon

  type rule = Ipaddr.V4.t

  module RuleMap = Map.Make(Ipaddr.V4)

  type callback = Cstruct.t -> unit Lwt.t

  type port = {
    callback: callback;
    mutable last_active_time: float;
  }

  type t = {
    netif: Netif.t;
    mutable rules: port RuleMap.t;
    mutable default_callback: callback;
  }

  let filesystem t =
    let xs =
      RuleMap.fold
        (fun ip t acc ->
          Printf.sprintf "%s last_active_time = %.1f" (Ipaddr.V4.to_string ip) t.last_active_time :: acc
        ) t.rules [] in
    Vfs.File.ro_of_string (String.concat "\n" xs)

  let remove t rule =
    Log.debug (fun f -> f "removing switch port for %s" (Ipaddr.V4.to_string rule));
    t.rules <- RuleMap.remove rule t.rules

  let callback t buf =
    (* Does the packet match any of our rules? *)
    let open Frame in
    match parse [ buf ] with
    | Ok (Ethernet { payload = Ipv4 { dst; _ }; _ }) ->
      if RuleMap.mem dst t.rules then begin
        let port = RuleMap.find dst t.rules in
        port.last_active_time <- Unix.gettimeofday ();
        port.callback buf
      end else begin
        Log.debug (fun f -> f "using default callback for packet for %s" (Ipaddr.V4.to_string dst));
        t.default_callback buf
      end
    | _ ->
      Log.debug (fun f -> f "using default callback for non-IPv4 frame");
      t.default_callback buf

  let connect netif =
    let rules = RuleMap.empty in
    let default_callback = fun _ -> Lwt.return_unit in
    let t = { netif; rules; default_callback } in
    Netif.listen netif @@ callback t >>= function
    | Error e -> Fmt.kstrf Lwt.fail_with "connect error: %a" Netif.pp_error e
    | Ok ()   -> Lwt.return t

  let lift_error = function
    | Error (#Mirage_device.error as e) -> Error (e :> error)
    | Error e -> Fmt.kstrf (fun e -> Error (`Unknown e)) "%a" Netif.pp_error e
    | Ok () -> Ok ()

  let write t buffer = Netif.write t.netif buffer >|= lift_error
  let writev t buffers = Netif.writev t.netif buffers >|= lift_error

  let listen t callback =
    t.default_callback <- callback;
    (* NOTE(samoht): I though the Net.listen were supposed to block? *)
    Lwt.return (Ok ())

  let disconnect t =
    Netif.disconnect t.netif

  let mac t = Netif.mac t.netif

  module Port = struct
    include DontCareAboutStats
    include ObviouslyCommon

    type _t = {
      switch: t;
      netif: Netif.t;
      rule: rule;
    }

    let write t buffer = Netif.write t.netif buffer >|= lift_error
    let writev t buffers = Netif.writev t.netif buffers >|= lift_error
    let listen t callback =
      Log.debug (fun f -> f "activating switch port for %s" (Ipaddr.V4.to_string t.rule));
      let last_active_time = Unix.gettimeofday () in
      let port = { callback; last_active_time } in
      t.switch.rules <- RuleMap.add t.rule port t.switch.rules;
      Lwt.return (Ok ())
    let disconnect t =
      Log.debug (fun f -> f "deactivating switch port for %s" (Ipaddr.V4.to_string t.rule));
      t.switch.rules <- RuleMap.remove t.rule t.switch.rules;
      Lwt.return_unit

    let mac t = Netif.mac t.netif

    type t = _t
  end

  let port t rule = { Port.switch = t; netif = t.netif; rule }

end
