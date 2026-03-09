
import { RouterProvider } from "react-router-dom";
import { router } from "./router";

// App.tsx is intentionally minimal.
// All routing, layout, and page logic lives in:
//   → src/router/index.tsx      (route definitions)
//   → src/components/shared/Layout.tsx  (sidebar + outlet)
//   → src/features/*/           (individual pages)

function App() {
  return <RouterProvider router={router} />;
}

export default App;