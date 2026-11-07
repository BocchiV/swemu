"""Live trace of the client's monster hit-reaction path (read-only hooks).
Usage: python hitreact_trace.py SECONDS > log
Waits for SoulWorker.exe, attaches, logs each call with its arguments."""
import sys, time, frida

SECS = float(sys.argv[1]) if len(sys.argv) > 1 else 60
JS = r"""
const m = Process.getModuleByName('SoulWorker64.dll');
const B = m.base;
const va = x => B.add(ptr(x).sub(ptr('0x180000000')));
let n = 0;
function out(s) { if (n++ < 4000) send(s); }
function mon(p) { try { return p.add(0x1738).readS16(); } catch (e) { return -99; } }
// hit_apply(attacker, target, trigger, pos, rot, 0, idx, combo, skill, p10, p11)
Interceptor.attach(va('0x180511960'), { onEnter(a) {
  const p10 = this.context.rsp.add(0x50).readU8(), p11 = this.context.rsp.add(0x58).readU8();
  out(`hit_apply target=${a[1]} idx=${this.context.rsp.add(0x38).readU32()} p10=${p10} p11=${p11} motion=${mon(a[1])}`);
}});
// CMonster vtable 0x248 -> FUN_180360ec0(mover, info, &reactMotion)
Interceptor.attach(va('0x180360ec0'), {
  onEnter(a) { this.m = a[0]; this.info = a[1];
    out(`  react enter mover=${a[0]} rtype=${a[1].add(4).readU8()} strength=${a[1].add(5).readU8()} b6=${a[1].add(6).readU8()} flag=${a[1].add(7).readU8()} p5b=${a[1].add(0x5b).readU8()} p5c=${a[1].add(0x5c).readU8()} reactMotion=${a[2].readS32()} motion=${mon(a[0])} defType=${a[0].add(0xe6ec).readU8()}`); },
  onLeave() { out(`  react leave motion=${mon(this.m)}`); } });
// GetDamageMotion (vtable 0x8d0)
Interceptor.attach(va('0x18035f430'), { onEnter(a) { this.r = a[1].toInt32() & 0xff; },
  onLeave(r) { out(`    getDamageMotion(rtype=${this.r}) -> ${r.toInt32()}`); } });
// SetMotion (vtable 0x218)
Interceptor.attach(va('0x1803398c0'), { onEnter(a) { out(`    setMotion mover=${a[0]} motion=${a[1].toInt32() & 0xffff}`); } });
// 0x250 hit show
Interceptor.attach(va('0x18038fcf0'), { onEnter(a) { out(`  hitShow p3=${a[2].toInt32() & 0xff}`); } });
// hit effect
Interceptor.attach(va('0x180365770'), { onEnter(a) { out(`    hitEffect id=${a[1].toInt32()}`); } });
Interceptor.attach(va('0x180365350'), { onEnter(a) { out(`    hitEffect2 id=${a[1].toInt32()}`); } });
// monster vtable 0x6f0 (iVar5)
Interceptor.attach(va('0x18033ae00'), { onLeave(r) { out(`    mon6f0 -> ${r.toInt32()}`); } });
// ACTION_SKILL_BT handler entry
Interceptor.attach(va('0x180dd0770'), { onEnter() { out('PKT 6/0x13'); } });
// CPlayer::ActionSkill(player, skill, trigger, count, pos, rot, combo, flag)
Interceptor.attach(va('0x1803fad80'), { onEnter(a) {
  out(`ActionSkill skill=${a[1].toInt32()} trigger=${a[2].toInt32() & 0xffff} n=${a[3].toInt32() & 0xff} playerMotion=${mon(a[0])}`); } });
// GetAttackEvent(player, trigger)
Interceptor.attach(va('0x180358680'), { onEnter(a) { this.t = a[1].toInt32(); },
  onLeave(r) { out(`  GetAttackEvent(${this.t}) -> ${r.isNull() ? 'NOT FOUND' : 'ok'}`); } });
send('hooks ready base=' + B);
"""

def main():
    pid = None
    deadline = time.time() + 600
    while pid is None and time.time() < deadline:
        for p in frida.get_local_device().enumerate_processes():
            if p.name.lower() == "soulworker.exe":
                pid = p.pid
        if pid is None:
            time.sleep(2)
    if pid is None:
        print("no game"); return
    time.sleep(20)  # let the DLL load
    s = frida.attach(pid)
    sc = s.create_script(JS)
    sc.on("message", lambda m, d: print(m.get("payload", m), flush=True))
    sc.load()
    print("attached", pid, flush=True)
    time.sleep(SECS)
    s.detach()
    print("done", flush=True)

main()
