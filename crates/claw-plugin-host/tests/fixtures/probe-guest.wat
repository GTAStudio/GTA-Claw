;; A real WebAssembly component that implements gta-claw:plugin/guest@1.0.0.
;;
;; This fixture is deliberately written in the component-model text format and
;; assembled at test time by the `wat` crate, so there is no committed binary,
;; no build step and nothing outside Rust in the loop. Every sandbox and
;; resource test in this crate runs THIS component inside Wasmtime.
;;
;; `invoke-tool` dispatches on the first byte of the tool name:
;;
;;   a  host-clock.now-ms          j  host-log.log
;;   b  host-random.get-bytes      k  host-tools.register
;;   c  host-fs.read-file          l  host-events.emit
;;   d  host-fs.write-file         s  spin forever
;;   e  host-fs.list-dir           m  grow memory until refused, then trap
;;   f  host-http.send             r  recurse until the stack is exhausted
;;   g  host-store.get             t  trap immediately
;;   h  host-store.set             x  succeed without touching the host
;;   i  host-config.get
;;
;; Host-call probes answer with a two byte string: "o0" when the host allowed
;; the call, or "e<n>" where <n> is the numeric error-code discriminant, so a
;; test can assert the exact outcome the guest observed.
;;
;; Static memory map (the memory is owned by the $mem module below):
;;    128..160  describe        return area   (plugin-info)
;;    192..208  activate        return area   (result<_, error>)
;;    224..244  handle-event    return area   (result<event-response, error>)
;;    256..272  invoke-tool     return area   (result<string, error>)
;;    288..312  host-call       return area
;;    512..514  two byte probe answer
;;   1024..     string literals
;;   4096..     bump allocations handed out by cabi_realloc
(component
  ;; ---------------------------------------------------------------- imports
  (import "gta-claw:plugin/host-log@1.0.0" (instance $host-log
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $level0 (enum "trace" "debug" "info" "warn" "error"))
    (export "level" (type $level (eq $level0)))
    (type $r (result (error $err)))
    (export "log" (func (param "lvl" $level) (param "message" string) (result $r)))
  ))

  (import "gta-claw:plugin/host-config@1.0.0" (instance $host-config
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $r (result (option string) (error $err)))
    (export "get" (func (param "key" string) (result $r)))
  ))

  (import "gta-claw:plugin/host-store@1.0.0" (instance $host-store
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $bytes (list u8))
    (type $rget (result (option $bytes) (error $err)))
    (type $rset (result (error $err)))
    (export "get" (func (param "key" string) (result $rget)))
    (export "set" (func (param "key" string) (param "value" $bytes) (result $rset)))
  ))

  (import "gta-claw:plugin/host-fs@1.0.0" (instance $host-fs
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $bytes (list u8))
    (type $names (list string))
    (type $rread (result $bytes (error $err)))
    (type $rwrite (result (error $err)))
    (type $rlist (result $names (error $err)))
    (export "read-file" (func (param "path" string) (result $rread)))
    (export "write-file" (func (param "path" string) (param "contents" $bytes) (result $rwrite)))
    (export "list-dir" (func (param "path" string) (result $rlist)))
  ))

  (import "gta-claw:plugin/host-http@1.0.0" (instance $host-http
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $bytes (list u8))
    (type $headers (list (tuple string string)))
    (type $request0 (record
      (field "method" string)
      (field "url" string)
      (field "headers" $headers)
      (field "body" (option $bytes))))
    (export "request" (type $request (eq $request0)))
    (type $response0 (record
      (field "status" u16)
      (field "headers" $headers)
      (field "body" $bytes)))
    (export "response" (type $response (eq $response0)))
    (type $r (result $response (error $err)))
    (export "send" (func (param "req" $request) (result $r)))
  ))

  (import "gta-claw:plugin/host-clock@1.0.0" (instance $host-clock
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $r (result u64 (error $err)))
    (export "now-ms" (func (result $r)))
  ))

  (import "gta-claw:plugin/host-random@1.0.0" (instance $host-random
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $bytes (list u8))
    (type $r (result $bytes (error $err)))
    (export "get-bytes" (func (param "len" u32) (result $r)))
  ))

  (import "gta-claw:plugin/host-tools@1.0.0" (instance $host-tools
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $tool0 (record
      (field "name" string)
      (field "summary" string)
      (field "input-schema" string)))
    (export "tool-descriptor" (type $tool (eq $tool0)))
    (type $r (result (error $err)))
    (export "register" (func (param "tool" $tool) (result $r)))
  ))

  (import "gta-claw:plugin/host-events@1.0.0" (instance $host-events
    (type $ec0 (enum "invalid-input" "permission-denied" "not-found" "conflict"
                    "resource-exhausted" "unsupported" "internal"))
    (export "error-code" (type $ec (eq $ec0)))
    (type $err0 (record (field "code" $ec) (field "message" string)))
    (export "error" (type $err (eq $err0)))
    (type $kind0 (enum "session-started" "session-ended" "message" "tool-result"
                      "config-changed" "heartbeat" "shutdown"))
    (export "event-kind" (type $kind (eq $kind0)))
    (type $event0 (record
      (field "kind" $kind)
      (field "sequence" u64)
      (field "source" string)
      (field "payload" string)))
    (export "event" (type $event (eq $event0)))
    (type $r (result (error $err)))
    (export "emit" (func (param "evt" $event) (result $r)))
  ))

  ;; ------------------------------------------------- memory and allocation
  (core module $mem
    (memory (export "memory") 1)
    (global $bump (mut i32) (i32.const 4096))
    (func (export "cabi_realloc")
      (param $orig i32) (param $orig-size i32) (param $align i32) (param $size i32)
      (result i32)
      (local $ret i32)
      (global.set $bump
        (i32.and
          (i32.add (global.get $bump) (i32.sub (local.get $align) (i32.const 1)))
          (i32.xor (i32.sub (local.get $align) (i32.const 1)) (i32.const -1))))
      (local.set $ret (global.get $bump))
      (global.set $bump (i32.add (global.get $bump) (local.get $size)))
      (block $enough
        (loop $grow
          (br_if $enough
            (i32.le_u (global.get $bump)
              (i32.mul (memory.size) (i32.const 65536))))
          (br_if $enough (i32.ne (memory.grow (i32.const 1)) (i32.const -1)))
          (unreachable)))
      (local.get $ret))
  )
  (core instance $meminst (instantiate $mem))
  (alias core export $meminst "memory" (core memory $memory))
  (alias core export $meminst "cabi_realloc" (core func $realloc))

  ;; ------------------------------------------------------- lowered imports
  (alias export $host-log "log" (func $log-fn))
  (alias export $host-config "get" (func $config-get-fn))
  (alias export $host-store "get" (func $store-get-fn))
  (alias export $host-store "set" (func $store-set-fn))
  (alias export $host-fs "read-file" (func $fs-read-fn))
  (alias export $host-fs "write-file" (func $fs-write-fn))
  (alias export $host-fs "list-dir" (func $fs-list-fn))
  (alias export $host-http "send" (func $http-send-fn))
  (alias export $host-clock "now-ms" (func $clock-now-fn))
  (alias export $host-random "get-bytes" (func $random-bytes-fn))
  (alias export $host-tools "register" (func $tools-register-fn))
  (alias export $host-events "emit" (func $events-emit-fn))

  (core func $log-lowered
    (canon lower (func $log-fn) (memory $memory) (realloc $realloc)))
  (core func $config-get-lowered
    (canon lower (func $config-get-fn) (memory $memory) (realloc $realloc)))
  (core func $store-get-lowered
    (canon lower (func $store-get-fn) (memory $memory) (realloc $realloc)))
  (core func $store-set-lowered
    (canon lower (func $store-set-fn) (memory $memory) (realloc $realloc)))
  (core func $fs-read-lowered
    (canon lower (func $fs-read-fn) (memory $memory) (realloc $realloc)))
  (core func $fs-write-lowered
    (canon lower (func $fs-write-fn) (memory $memory) (realloc $realloc)))
  (core func $fs-list-lowered
    (canon lower (func $fs-list-fn) (memory $memory) (realloc $realloc)))
  (core func $http-send-lowered
    (canon lower (func $http-send-fn) (memory $memory) (realloc $realloc)))
  (core func $clock-now-lowered
    (canon lower (func $clock-now-fn) (memory $memory) (realloc $realloc)))
  (core func $random-bytes-lowered
    (canon lower (func $random-bytes-fn) (memory $memory) (realloc $realloc)))
  (core func $tools-register-lowered
    (canon lower (func $tools-register-fn) (memory $memory) (realloc $realloc)))
  (core func $events-emit-lowered
    (canon lower (func $events-emit-fn) (memory $memory) (realloc $realloc)))

  ;; ------------------------------------------------------------ the guest
  (core module $guest
    (import "env" "memory" (memory 1))
    (import "env" "log" (func $h-log (param i32 i32 i32 i32)))
    (import "env" "config-get" (func $h-config-get (param i32 i32 i32)))
    (import "env" "store-get" (func $h-store-get (param i32 i32 i32)))
    (import "env" "store-set" (func $h-store-set (param i32 i32 i32 i32 i32)))
    (import "env" "fs-read" (func $h-fs-read (param i32 i32 i32)))
    (import "env" "fs-write" (func $h-fs-write (param i32 i32 i32 i32 i32)))
    (import "env" "fs-list" (func $h-fs-list (param i32 i32 i32)))
    (import "env" "http-send"
      (func $h-http (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)))
    (import "env" "clock-now" (func $h-clock (param i32)))
    (import "env" "random-bytes" (func $h-random (param i32 i32)))
    (import "env" "tools-register"
      (func $h-tools (param i32 i32 i32 i32 i32 i32 i32)))
    (import "env" "events-emit"
      (func $h-events (param i32 i64 i32 i32 i32 i32 i32)))

    ;; 1024 "gta-claw-fixture-probe"  (22)
    ;; 1048 "ok"                      (2)
    ;; 1052 "probe"                   (5)
    ;; 1060 "k"                       (1)
    ;; 1064 "probe.txt"               (9)
    ;; 1076 "https://example.invalid/probe" (29)
    ;; 1108 "probe tool"              (10)
    ;; 1120 "{}"                      (2)
    ;; 1124 "GET"                     (3)
    ;; 1132 "."                       (1)
    ;; 1136 "unknown probe"           (13)
    ;; 1152 "../escape.txt"           (13)
    ;; 1168 "/etc/passwd"             (11)
    (data (i32.const 1024) "gta-claw-fixture-probe")
    (data (i32.const 1048) "ok")
    (data (i32.const 1052) "probe")
    (data (i32.const 1060) "k")
    (data (i32.const 1064) "probe.txt")
    (data (i32.const 1076) "https://example.invalid/probe")
    (data (i32.const 1108) "probe tool")
    (data (i32.const 1120) "{}")
    (data (i32.const 1124) "GET")
    (data (i32.const 1132) ".")
    (data (i32.const 1136) "unknown probe")
    (data (i32.const 1152) "../escape.txt")
    (data (i32.const 1168) "/etc/passwd")

    ;; result<string, error> holding an ok string.
    (func $ok-string (param $ptr i32) (param $len i32) (result i32)
      (i32.store8 (i32.const 256) (i32.const 0))
      (i32.store (i32.const 260) (local.get $ptr))
      (i32.store (i32.const 264) (local.get $len))
      (i32.const 256))

    ;; Turns a host-call return area into the two byte probe answer.
    (func $answer (param $area i32) (param $code-offset i32) (result i32)
      (if (i32.eqz (i32.load8_u (local.get $area)))
        (then
          (i32.store8 (i32.const 512) (i32.const 111))
          (i32.store8 (i32.const 513) (i32.const 48)))
        (else
          (i32.store8 (i32.const 512) (i32.const 101))
          (i32.store8 (i32.const 513)
            (i32.add (i32.const 48)
              (i32.load8_u (i32.add (local.get $area) (local.get $code-offset)))))))
      (call $ok-string (i32.const 512) (i32.const 2)))

    (func $recurse (param $depth i32) (result i32)
      (i32.add (i32.const 1) (call $recurse (i32.add (local.get $depth) (i32.const 1)))))

    (func (export "describe") (result i32)
      (i32.store (i32.const 128) (i32.const 1024))
      (i32.store (i32.const 132) (i32.const 22))
      (i32.store (i32.const 136) (i32.const 0))
      (i32.store (i32.const 140) (i32.const 1))
      (i32.store (i32.const 144) (i32.const 0))
      (i32.store (i32.const 148) (i32.const 1))
      (i32.store (i32.const 152) (i32.const 0))
      (i32.store (i32.const 156) (i32.const 0))
      (i32.const 128))

    (func (export "activate") (result i32)
      (i32.store8 (i32.const 192) (i32.const 0))
      (i32.const 192))

    (func (export "deactivate") (result i32)
      (i32.store8 (i32.const 192) (i32.const 0))
      (i32.const 192))

    (func (export "handle-event")
      (param $kind i32) (param $seq i64)
      (param $src i32) (param $src-len i32)
      (param $pay i32) (param $pay-len i32)
      (result i32)
      (i32.store8 (i32.const 224) (i32.const 0))
      (i32.store8 (i32.const 228) (i32.eq (local.get $kind) (i32.const 5)))
      (if (i32.eq (local.get $kind) (i32.const 5))
        (then
          (i32.store8 (i32.const 232) (i32.const 1))
          (i32.store (i32.const 236) (i32.const 1048))
          (i32.store (i32.const 240) (i32.const 2)))
        (else
          (i32.store8 (i32.const 232) (i32.const 0))))
      (i32.const 224))

    (func (export "invoke-tool")
      (param $name i32) (param $name-len i32)
      (param $input i32) (param $input-len i32)
      (result i32)
      (local $selector i32)
      (if (i32.eqz (local.get $name-len))
        (then (return (call $unknown))))
      (local.set $selector (i32.load8_u (local.get $name)))

      ;; a: host-clock.now-ms
      (if (i32.eq (local.get $selector) (i32.const 97))
        (then
          (call $h-clock (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 8)))))
      ;; b: host-random.get-bytes
      (if (i32.eq (local.get $selector) (i32.const 98))
        (then
          (call $h-random (i32.const 8) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; c: host-fs.read-file
      (if (i32.eq (local.get $selector) (i32.const 99))
        (then
          (call $h-fs-read (i32.const 1064) (i32.const 9) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; d: host-fs.write-file
      (if (i32.eq (local.get $selector) (i32.const 100))
        (then
          (call $h-fs-write
            (i32.const 1064) (i32.const 9)
            (i32.const 1048) (i32.const 2)
            (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; e: host-fs.list-dir on the granted directory
      (if (i32.eq (local.get $selector) (i32.const 101))
        (then
          (call $h-fs-list (i32.const 1052) (i32.const 5) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; n: host-fs.list-dir with a `.` segment
      (if (i32.eq (local.get $selector) (i32.const 110))
        (then
          (call $h-fs-list (i32.const 1132) (i32.const 1) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; p: host-fs.read-file trying to climb out of the granted root
      (if (i32.eq (local.get $selector) (i32.const 112))
        (then
          (call $h-fs-read (i32.const 1152) (i32.const 13) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; q: host-fs.read-file with an absolute path
      (if (i32.eq (local.get $selector) (i32.const 113))
        (then
          (call $h-fs-read (i32.const 1168) (i32.const 11) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; f: host-http.send
      (if (i32.eq (local.get $selector) (i32.const 102))
        (then
          (call $h-http
            (i32.const 1124) (i32.const 3)
            (i32.const 1076) (i32.const 29)
            (i32.const 0) (i32.const 0)
            (i32.const 0) (i32.const 0) (i32.const 0)
            (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; g: host-store.get
      (if (i32.eq (local.get $selector) (i32.const 103))
        (then
          (call $h-store-get (i32.const 1060) (i32.const 1) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; h: host-store.set
      (if (i32.eq (local.get $selector) (i32.const 104))
        (then
          (call $h-store-set
            (i32.const 1060) (i32.const 1)
            (i32.const 1048) (i32.const 2)
            (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; i: host-config.get
      (if (i32.eq (local.get $selector) (i32.const 105))
        (then
          (call $h-config-get (i32.const 1060) (i32.const 1) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; j: host-log.log
      (if (i32.eq (local.get $selector) (i32.const 106))
        (then
          (call $h-log (i32.const 2) (i32.const 1052) (i32.const 5) (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; k: host-tools.register
      (if (i32.eq (local.get $selector) (i32.const 107))
        (then
          (call $h-tools
            (i32.const 1052) (i32.const 5)
            (i32.const 1108) (i32.const 10)
            (i32.const 1120) (i32.const 2)
            (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; l: host-events.emit
      (if (i32.eq (local.get $selector) (i32.const 108))
        (then
          (call $h-events
            (i32.const 5) (i64.const 0)
            (i32.const 1052) (i32.const 5)
            (i32.const 1120) (i32.const 2)
            (i32.const 288))
          (return (call $answer (i32.const 288) (i32.const 4)))))
      ;; s: spin forever
      (if (i32.eq (local.get $selector) (i32.const 115))
        (then
          (loop $spin (br $spin))))
      ;; m: grow until the limiter refuses, then trap
      (if (i32.eq (local.get $selector) (i32.const 109))
        (then
          (loop $grow
            (if (i32.eq (memory.grow (i32.const 16)) (i32.const -1))
              (then (unreachable)))
            (br $grow))))
      ;; r: recurse until the stack is exhausted
      (if (i32.eq (local.get $selector) (i32.const 114))
        (then
          (drop (call $recurse (i32.const 0)))))
      ;; t: trap
      (if (i32.eq (local.get $selector) (i32.const 116))
        (then (unreachable)))
      ;; x: no host call at all
      (if (i32.eq (local.get $selector) (i32.const 120))
        (then (return (call $ok-string (i32.const 1048) (i32.const 2)))))
      (call $unknown))

    (func $unknown (result i32)
      (i32.store8 (i32.const 256) (i32.const 1))
      (i32.store8 (i32.const 260) (i32.const 0))
      (i32.store (i32.const 264) (i32.const 1136))
      (i32.store (i32.const 268) (i32.const 13))
      (i32.const 256))
  )

  (core instance $guestinst (instantiate $guest
    (with "env" (instance
      (export "memory" (memory $memory))
      (export "log" (func $log-lowered))
      (export "config-get" (func $config-get-lowered))
      (export "store-get" (func $store-get-lowered))
      (export "store-set" (func $store-set-lowered))
      (export "fs-read" (func $fs-read-lowered))
      (export "fs-write" (func $fs-write-lowered))
      (export "fs-list" (func $fs-list-lowered))
      (export "http-send" (func $http-send-lowered))
      (export "clock-now" (func $clock-now-lowered))
      (export "random-bytes" (func $random-bytes-lowered))
      (export "tools-register" (func $tools-register-lowered))
      (export "events-emit" (func $events-emit-lowered))
    ))
  ))

  ;; ------------------------------------------------------- lifted exports
  (type $ec (enum "invalid-input" "permission-denied" "not-found" "conflict"
                  "resource-exhausted" "unsupported" "internal"))
  (type $err (record (field "code" $ec) (field "message" string)))
  (type $semver (record (field "major" u32) (field "minor" u32) (field "patch" u32)))
  (type $plugin-info (record
    (field "id" string)
    (field "version" $semver)
    (field "abi-version" $semver)))
  (type $event-kind (enum "session-started" "session-ended" "message" "tool-result"
                          "config-changed" "heartbeat" "shutdown"))
  (type $event (record
    (field "kind" $event-kind)
    (field "sequence" u64)
    (field "source" string)
    (field "payload" string)))
  (type $event-response (record
    (field "handled" bool)
    (field "note" (option string))))
  (type $unit-result (result (error $err)))
  (type $event-result (result $event-response (error $err)))
  (type $string-result (result string (error $err)))

  (type $describe-ty (func (result $plugin-info)))
  (type $lifecycle-ty (func (result $unit-result)))
  (type $handle-event-ty (func (param "evt" $event) (result $event-result)))
  (type $invoke-tool-ty
    (func (param "name" string) (param "input" string) (result $string-result)))

  (alias core export $guestinst "describe" (core func $describe-core))
  (alias core export $guestinst "activate" (core func $activate-core))
  (alias core export $guestinst "deactivate" (core func $deactivate-core))
  (alias core export $guestinst "handle-event" (core func $handle-event-core))
  (alias core export $guestinst "invoke-tool" (core func $invoke-tool-core))

  (func $describe (type $describe-ty)
    (canon lift (core func $describe-core) (memory $memory) (realloc $realloc)))
  (func $activate (type $lifecycle-ty)
    (canon lift (core func $activate-core) (memory $memory) (realloc $realloc)))
  (func $deactivate (type $lifecycle-ty)
    (canon lift (core func $deactivate-core) (memory $memory) (realloc $realloc)))
  (func $handle-event (type $handle-event-ty)
    (canon lift (core func $handle-event-core) (memory $memory) (realloc $realloc)))
  (func $invoke-tool (type $invoke-tool-ty)
    (canon lift (core func $invoke-tool-core) (memory $memory) (realloc $realloc)))

  (instance $guest-exports
    (export "error-code" (type $ec))
    (export "error" (type $err))
    (export "semver" (type $semver))
    (export "plugin-info" (type $plugin-info))
    (export "event-kind" (type $event-kind))
    (export "event" (type $event))
    (export "event-response" (type $event-response))
    (export "describe" (func $describe))
    (export "activate" (func $activate))
    (export "deactivate" (func $deactivate))
    (export "handle-event" (func $handle-event))
    (export "invoke-tool" (func $invoke-tool)))
  (export "gta-claw:plugin/guest@1.0.0" (instance $guest-exports))
)
