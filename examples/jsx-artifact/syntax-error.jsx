export default function App() {
  const items = [1, 2, 3];
  return (
    <ul>
      {items.map((item) => <li key={item}>{item}</li>}
    </ul>
  );
}
