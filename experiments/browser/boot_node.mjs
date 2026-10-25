// E09 in Node: boot the guest under v86 (no browser), print its serial console, exit 0 when
// hello held and the guest finished.   node experiments/browser/boot_node.mjs [out-dir]
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(process.argv[2] || HERE + "/out");
const { V86 } = await import(HERE + "/node_modules/v86/build/libv86.mjs");
const t0 = Date.now();
const emulator = new V86({
  wasm_path: HERE + "/node_modules/v86/build/v86.wasm",
  bios: { url: HERE + "/cache/seabios.bin" }, vga_bios: { url: HERE + "/cache/vgabios.bin" },
  bzimage: { url: OUT + "/vmlinuz-virt" }, initrd: { url: OUT + "/initramfs.cpio.gz" },
  cmdline: "console=ttyS0,115200 rdinit=/init panic=5 tsc=unstable",
  memory_size: 512 * 1024 * 1024, vga_memory_size: 2 * 1024 * 1024,
  autostart: true, disable_keyboard: true, disable_mouse: true, disable_speaker: true,
});
const dec = new TextDecoder();
let line = "", helloExit = null;
emulator.add_listener("serial0-output-byte", (b) => {
  const c = dec.decode(new Uint8Array([b]), { stream: true });
  if (!c) return;
  if (c === "\n") {
    console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s] ${line}`);
    if (line.startsWith("SHARNESS-HELLO-EXIT")) helloExit = Number(line.split(" ").pop());
    if (line.includes("SHARNESS-DONE")) {
      console.log(`node ${process.version} · v86 in Node · wall clock ${((Date.now() - t0) / 1000).toFixed(1)}s · hello exit ${helloExit}`);
      setTimeout(() => process.exit(helloExit === 0 ? 0 : 1), 300);
    }
    line = "";
  } else if (c !== "\r") line += c;
});
setTimeout(() => { console.log("TIMEOUT: the guest did not finish in 25 minutes"); process.exit(2); }, 25 * 60 * 1000);
