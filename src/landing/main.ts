import "./landing.css";

type Point3D = { x: number; y: number; z: number };

const canvas = document.querySelector<HTMLCanvasElement>("#sovereign-canvas");
const year = document.querySelector<HTMLElement>("#copyright-year");

if (year) year.textContent = String(new Date().getFullYear());

if (canvas) {
  const context = canvas.getContext("2d");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let width = 0;
  let height = 0;
  let animationFrame = 0;
  let previousFrame = 0;

  const rotate = (point: Point3D, time: number): Point3D => {
    const yaw = time * 0.13 + 0.65;
    const pitch = time * 0.07 - 0.55;
    const cy = Math.cos(yaw);
    const sy = Math.sin(yaw);
    const cp = Math.cos(pitch);
    const sp = Math.sin(pitch);
    const x = point.x * cy - point.z * sy;
    const z = point.x * sy + point.z * cy;

    return { x, y: point.y * cp - z * sp, z: point.y * sp + z * cp };
  };

  const knotPoint = (position: number, time: number): Point3D => {
    const radius = 2 + Math.cos(3 * position);
    const pulse = Math.sin(position * 7 + time * 0.35) * 0.055;

    return {
      x: (radius + pulse) * Math.cos(2 * position),
      y: (radius + pulse) * Math.sin(2 * position),
      z: Math.sin(3 * position) + pulse,
    };
  };

  const draw = (time = 0) => {
    if (!context || width === 0 || height === 0) return;

    const seconds = time / 1000;
    const scale = Math.min(width, height) * 0.15;
    const centerX = width * 0.56;
    const centerY = height * 0.48;
    const segments = Array.from({ length: 180 }, (_, index) => {
      const start = rotate(knotPoint((index / 180) * Math.PI * 2, seconds), seconds);
      const end = rotate(knotPoint(((index + 1) / 180) * Math.PI * 2, seconds), seconds);
      return { start, end, depth: (start.z + end.z) / 2 };
    }).sort((a, b) => a.depth - b.depth);

    context.clearRect(0, 0, width, height);
    context.lineCap = "round";
    context.lineJoin = "round";

    for (const segment of segments) {
      const depth = (segment.depth + 3.2) / 6.4;
      const shade = Math.round(226 - depth * 90);
      context.beginPath();
      context.moveTo(centerX + segment.start.x * scale, centerY + segment.start.y * scale);
      context.lineTo(centerX + segment.end.x * scale, centerY + segment.end.y * scale);
      context.strokeStyle = `rgb(${shade} ${shade} ${shade})`;
      context.lineWidth = scale * (0.44 + depth * 0.16);
      context.stroke();
    }

    context.strokeStyle = "rgb(255 255 255 / 0.3)";
    context.lineWidth = 1;
    for (let index = 0; index < 12; index += 1) {
      const offset = index * 0.018;
      context.beginPath();
      for (let pointIndex = 0; pointIndex <= 180; pointIndex += 1) {
        const point = rotate(knotPoint((pointIndex / 180) * Math.PI * 2 + offset, seconds), seconds);
        const x = centerX + point.x * scale;
        const y = centerY + point.y * scale;
        if (pointIndex === 0) context.moveTo(x, y);
        else context.lineTo(x, y);
      }
      context.stroke();
    }
  };

  const animate = (time: number) => {
    if (time - previousFrame > 32) {
      draw(time);
      previousFrame = time;
    }
    animationFrame = window.requestAnimationFrame(animate);
  };

  const resize = () => {
    const bounds = canvas.getBoundingClientRect();
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.max(1, Math.round(bounds.width * ratio));
    height = Math.max(1, Math.round(bounds.height * ratio));
    canvas.width = width;
    canvas.height = height;
    context?.setTransform(ratio, 0, 0, ratio, 0, 0);
    width = bounds.width;
    height = bounds.height;
    draw();
  };

  const setMotion = () => {
    window.cancelAnimationFrame(animationFrame);
    if (reducedMotion.matches) draw();
    else animationFrame = window.requestAnimationFrame(animate);
  };

  new ResizeObserver(resize).observe(canvas);
  reducedMotion.addEventListener("change", setMotion);
  resize();
  setMotion();
}
