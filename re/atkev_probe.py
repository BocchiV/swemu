import sys, time, frida
JS = r"""
const B = Process.getModuleByName('SoulWorker64.dll').base;
const va = x => B.add(ptr(x).sub(ptr('0x180000000')));
let n = 0;
Interceptor.attach(va('0x180358680'), { onEnter(a) { this.k = a[1].toInt32(); this.ra = this.returnAddress.sub(B).add(ptr('0x180000000')); },
  onLeave(r) { if (n++ > 300) return;
    let s = `key=${this.k} caller=${this.ra}`;
    if (!r.isNull()) { try { s += ` type=${r.add(16).readU8()} eid=${r.add(18).readS16()} name=${r.add(20).readCString()} t=${r.add(148).readFloat().toFixed(3)}`; } catch (e) { s += ' ?'; } }
    else s += ' NOT FOUND';
    send(s); } });
send('ready');
"""
pid = None
while pid is None:
    l = [p.pid for p in frida.get_local_device().enumerate_processes() if p.name.lower() == "soulworker.exe"]
    if l: pid = l[0]; time.sleep(25)
    else: time.sleep(2)
s = frida.attach(pid); sc = s.create_script(JS)
sc.on("message", lambda m, d: print(m.get("payload", m), flush=True)); sc.load()
time.sleep(float(sys.argv[1])); s.detach()
