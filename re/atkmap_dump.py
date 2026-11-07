"""Dump the player's client-side attack-event map: key -> trigger name.
Waits for one GetAttackEvent call on the player (needs one attack), then
queries keys 0..20000 through the same exported function."""
import sys, time, frida, json
JS = r"""
const gp = Process.getModuleByName('GamePlugin.vPlugin');
const ex = gp.enumerateExports().find(e => e.name.indexOf('?GetAttackEvent@AnimationTriggerDetectorComponent@@') === 0);
const f = new NativeFunction(ex.address, 'pointer', ['pointer', 'int']);
let done = false;
Interceptor.attach(ex.address, { onEnter(a) { this.c = a[0]; },
  onLeave(r) {
    if (done || r.isNull()) return;
    done = true;
    const comp = this.c;
    setTimeout(() => {
      const out = [];
      for (let k = 0; k < 20000; k++) {
        const t = f(comp, k);
        if (!t.isNull()) {
          let nm = '?'; try { nm = t.add(20).readCString(); } catch (e) {}
          out.push([k, t.add(16).readU8(), nm, t.add(148).readFloat()]);
        }
      }
      send({map: out});
    }, 10);
  } });
send('ready ' + ex.name);
"""
pid = None
while pid is None:
    l = [p.pid for p in frida.get_local_device().enumerate_processes() if p.name.lower() == "soulworker.exe"]
    if l: pid = l[0]
    else: time.sleep(2)
s = frida.attach(pid); sc = s.create_script(JS)
got = []
def on(m, d):
    p = m.get("payload", m)
    if isinstance(p, dict) and "map" in p:
        got.append(p["map"])
    else:
        print(p, flush=True)
sc.on("message", on); sc.load()
t0 = time.time()
while not got and time.time() - t0 < float(sys.argv[1]):
    time.sleep(0.5)
s.detach()
if got:
    json.dump(got[0], open(sys.argv[2], "w"), indent=0)
    print("keys", len(got[0]))
