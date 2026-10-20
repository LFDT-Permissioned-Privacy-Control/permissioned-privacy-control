import { ApiReferenceClient } from "@/components/api-reference-client";

export const metadata = {
  title: "API Reference (Interactive)",
  description:
    "Interactive OpenAPI reference for the Open Privacy Suite REST API, generated from the code on every merge.",
};

export default function ApiReferencePage() {
  return <ApiReferenceClient />;
}
