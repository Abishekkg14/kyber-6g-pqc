// 3D block density map (three.js): column height = log(number of telemetry fixes in the cell).
import * as THREE from "three";
import {OrbitControls} from "three/addons/controls/OrbitControls.js";

const canvas = document.getElementById("voxel");
const renderer = new THREE.WebGLRenderer({canvas, antialias: false});
renderer.setPixelRatio(1);
const scene = new THREE.Scene();
scene.background = new THREE.Color(0x87ceeb);
scene.fog = new THREE.Fog(0x87ceeb, 60, 140);
const camera = new THREE.PerspectiveCamera(55, 2, 0.1, 500);
camera.position.set(28, 30, 38);
const controls = new OrbitControls(camera, canvas);
controls.target.set(0, 0, 0);
scene.add(new THREE.HemisphereLight(0xffffff, 0x445522, 1.1));
const sun = new THREE.DirectionalLight(0xffffff, 1.2); sun.position.set(30, 50, 20); scene.add(sun);

const N = 24, size = 1;
const ground = new THREE.Mesh(new THREE.BoxGeometry(N + 2, 1, N + 2), new THREE.MeshLambertMaterial({color: 0x5d9a2f}));
ground.position.y = -0.5; scene.add(ground);
const dirt = new THREE.Mesh(new THREE.BoxGeometry(N + 2, 2, N + 2), new THREE.MeshLambertMaterial({color: 0x79553a}));
dirt.position.y = -2; scene.add(dirt);
const geo = new THREE.BoxGeometry(size * 0.96, size, size * 0.96);
const mat = new THREE.MeshLambertMaterial();
const MAXB = N * N * 16;
const mesh = new THREE.InstancedMesh(geo, mat, MAXB);
mesh.count = 0; scene.add(mesh);
const LEVEL = [0x6aad35, 0x8f8f8f, 0xe0c341, 0xffaa00, 0xc8261e];   // grass, stone, gold, orange, redstone
let built = null;
const note = document.getElementById("voxNote");

function build(grid) {
  const m = new THREE.Matrix4(), col = new THREE.Color();
  let k = 0, max = 0;
  grid.grid.forEach((row) => row.forEach((v) => (max = Math.max(max, v))));
  grid.grid.forEach((row, i) => row.forEach((v, j) => {
    if (!v) return;
    const h = Math.max(1, Math.round(1 + Math.log2(1 + v) / Math.log2(1 + max) * 15));
    for (let y = 0; y < h && k < MAXB; y++) {
      m.makeTranslation(j - N / 2 + 0.5, y + 0.5, (N - 1 - i) - N / 2 + 0.5);
      mesh.setMatrixAt(k, m);
      mesh.setColorAt(k, col.setHex(LEVEL[Math.min(LEVEL.length - 1, Math.floor(y / 3.2))]));
      k++;
    }
  }));
  mesh.count = k;
  mesh.instanceMatrix.needsUpdate = true;
  if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  const b = grid.bounds;
  note.textContent = `${k} blocks · peak ${max} fixes in one cell · area ${b[0].toFixed(5)},${b[1].toFixed(5)} → ${b[2].toFixed(5)},${b[3].toFixed(5)} · north is away from the camera's start`;
}

function resize() {
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (canvas.width !== w || canvas.height !== h) { renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix(); }
}
function tick() {
  const visible = canvas.offsetParent !== null;
  if (visible) {
    const st = window.K6G_STATE, g = st && st.analytics && st.analytics.grid;
    if (g && g.grid && g.grid.length && st.analytics.computed !== built) { build(g); built = st.analytics.computed; }
    if (!g || !g.grid || !g.grid.length) note.textContent = "No GNSS fixes stored yet — columns rise where the UAV spends time once the receiver has a fix.";
    resize(); controls.update(); renderer.render(scene, camera);
  }
  requestAnimationFrame(tick);
}
tick();
