"""Why the stamina bar stays hidden: watch the 3/0x34 stat handler, the
stamina display update FUN_180c4faa0 and the global gate 0x181a1e7d4."""
import sys, time, frida
JS = r"""
const B = Process.getModuleByName('SoulWorker64.dll').base;
const va = x => B.add(ptr(x).sub(ptr('0x180000000')));
const gate = va('0x181a1e7d4');
send('gate=' + gate.readS32());
let n = 0;
Interceptor.attach(va('0x180dd9890'), { onEnter(a) { if (n++ < 300) { let h='?'; try { const d = a[1].add(0xb).readPointer(); const len = a[1].add(0x1b).readU16(); h = len + ':' + Array.from(new Uint8Array(d.readByteArray(Math.min(len, 48)))).map(b => b.toString(16).padStart(2,'0')).join(''); } catch (e) { h = 'err ' + e; } let ui='?'; try { const p1 = a[0].add(0x140).readPointer(); ui = 'p1=' + p1 + (p1.isNull() ? '' : ' f71c=' + p1.add(0x71c).readU8() + ' ui548=' + p1.add(0x548).readPointer() + ' ui528=' + p1.add(0x528).readPointer()); } catch (e) { ui = 'err ' + e; } send('stat34 gate=' + gate.readS32() + ' ' + h + ' ' + ui); } } });
Interceptor.attach(va('0x180c4faa0'), { onEnter(a) { send(`staminaUI cur=${a[1].toInt32()} max=${a[2].toInt32()} delta=${a[3].toInt32()}`); } });
setInterval(() => send('gate=' + gate.readS32()), 15000);
"""
pid = None
while pid is None:
    l = [p.pid for p in frida.get_local_device().enumerate_processes() if p.name.lower() == "soulworker.exe"]
    if l: pid = l[0]
    else: time.sleep(2)
s = frida.attach(pid); sc = s.create_script(JS)
sc.on("message", lambda m, d: print(time.strftime('%H:%M:%S'), m.get("payload", m), flush=True)); sc.load()
time.sleep(float(sys.argv[1])); s.detach()
