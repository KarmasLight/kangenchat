import { ReactNode, Suspense } from "react";

export default function WidgetLayout({ children }: { children: ReactNode }) {
  return <Suspense fallback={null}>{children}</Suspense>;
}
