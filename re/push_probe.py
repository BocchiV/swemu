"""Measure how far the client pushes a monster on each hit reaction.
Hooks Mover_ApplyReact (FUN_180360ec0) and samples the mover's position
(VisObject3D_cl::GetPosition) at the hit and 0.3 / 0.8 / 1.5 s later."""
import sys, time, frida
JS = r"""
const B = Process.getModuleByName('SoulWorker64.dll').base;
const va = x => B.add(ptr(x).sub(ptr('0x180000000')));
let gp = null;
for (const m of ['Vision.dll', 'VisionDX11.dll']) {
  try { const e = Process.getModuleByName(m).enumerateExports().find(e => e.name.indexOf('?GetPosition@VisObject3D_cl@@QEBAAEBVhkvVec3@@XZ') === 0);
        if (e) { gp = new NativeFunction(e.address, 'pointer', ['pointer']); break; } } catch (e) {}
}
function pos(m) { const p = gp(m); return [p.readFloat(), p.add(4).readFloat(), p.add(8).readFloat()]; }
let n = 0;
Interceptor.attach(va('0x180360ec0'), { onEnter(a) {
  if (n++ > 400) return;
  const m = a[0]; const p0 = pos(m); const t0 = Date.now();
  const rt = a[1].add(4).readU8();
  [300, 800, 1500].forEach(dt => setTimeout(() => {
    try { const p = pos(m); const d = Math.hypot(p[0]-p0[0], p[1]-p0[1]);
      send(`m=${m} rtype=${rt} +${dt}ms moved=${d.toFixed(0)} at=${p.map(v=>v.toFixed(0))}`); } catch (e) {}
  }, dt));
}});
send('ready gp=' + (gp !== null));
"""
pid = None
while pid is None:
    l = [p.pid for p in frida.get_local_device().enumerate_processes() if p.name.lower() == "soulworker.exe"]
    if l: pid = l[0]
    else: time.sleep(2)
s = frida.attach(pid); sc = s.create_script(JS)
sc.on("message", lambda m, d: print(time.time(), m.get("payload", m), flush=True)); sc.load()
time.sleep(float(sys.argv[1])); s.detach()
