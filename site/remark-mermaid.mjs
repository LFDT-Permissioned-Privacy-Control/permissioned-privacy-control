import { visit } from "unist-util-visit";

/**
 * Remark plugin that transforms ```mermaid code blocks into
 * <Mermaid chart="..." /> JSX elements rendered client-side.
 */
export default function remarkMermaid() {
  return (ast) => {
    const codeblocks = [];

    visit(ast, "code", (node, index, parent) => {
      if (node.lang === "mermaid" && index !== undefined && parent) {
        codeblocks.push({ node, index, parent });
      }
    });

    if (codeblocks.length === 0) return;

    // Replace code blocks with <Mermaid chart="..." /> (reverse order to keep indices valid)
    for (let i = codeblocks.length - 1; i >= 0; i--) {
      const { index, parent } = codeblocks[i];
      parent.children.splice(index, 1, {
        type: "mdxJsxFlowElement",
        name: "Mermaid",
        attributes: [
          {
            type: "mdxJsxAttribute",
            name: "chart",
            value: codeblocks[i].node.value,
          },
        ],
        children: [],
      });
    }

    // Add import for the Mermaid component (after splices to avoid index shift)
    ast.children.unshift({
      type: "mdxjsEsm",
      data: {
        estree: {
          type: "Program",
          sourceType: "module",
          body: [
            {
              type: "ImportDeclaration",
              specifiers: [
                {
                  type: "ImportSpecifier",
                  imported: { type: "Identifier", name: "Mermaid" },
                  local: { type: "Identifier", name: "Mermaid" },
                },
              ],
              source: {
                type: "Literal",
                value: "@/components/mdx/mermaid",
              },
            },
          ],
        },
      },
    });
  };
}
