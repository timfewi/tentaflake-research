# Internal fragment for the complete deployment module. The service's workers
# inherit this slice and /tmp backing; no per-worker 512 MiB tmpfs is created.
{ lib, serviceUid }:
let
  units = [
    "agent-research"
    "agent-research-egress"
    "agent-research-egress-control"
  ];
  common = {
    Slice = "agent-research.slice";
    Delegate = false;
    KillMode = "control-group";
    SendSIGKILL = true;
    TimeoutStopSec = 30;
    OOMPolicy = "stop";
    LimitCORE = 0;
    LimitNOFILE = 4096;
    UMask = "0077";
  };
in
{
  systemd.slices.agent-research = {
    description = "Aggregate research service and worker resource budget";
    sliceConfig = {
      MemoryAccounting = true;
      MemoryMax = "2147483648";
      MemorySwapMax = "0";
      TasksAccounting = true;
      TasksMax = 1024;
    };
  };
  systemd.services = lib.genAttrs units (name: {
    serviceConfig =
      common
      // (
        if name == "agent-research" then
          {
            # All parser/browser scratch and strict archives originate below /tmp.
            # Keep the service's loopback and namespace permissions in the full module.
            PrivateTmp = false;
            TemporaryFileSystem =
              assert lib.assertMsg (
                builtins.isInt serviceUid && serviceUid > 0 && serviceUid < 4294967295
              ) "Research scratch ownership requires an explicit non-root service UID";
              [
                "/tmp:rw,nosuid,nodev,noexec,size=536870912,mode=0700,uid=${toString serviceUid}"
              ];
            InaccessiblePaths = [
              "/var/tmp"
              "/dev/shm"
            ];
          }
        else
          {
            # These components need only their projected runtime sockets/lease files.
            # They must not receive an independent, writable temporary allocation.
            InaccessiblePaths = [
              "/tmp"
              "/var/tmp"
              "/dev/shm"
            ];
          }
      );
  });
}
