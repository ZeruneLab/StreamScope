type PlanManifest = {
  id: string;
  name: string;
  version: string;
  dependencies: { id: string; version: string }[];
};

// Resolve and validate the complete graph before requesting consent or changing the registry.
export async function planPluginInstallation<T extends { manifest: PlanManifest }>(
  root: T,
  resolve: (id: string, requirements: string[], selectedVersion?: string) => Promise<T | undefined>,
): Promise<T[]> {
  const selected = new Map<string, T>([[root.manifest.id, root]]);
  const active = new Set<string>();
  const done = new Set<string>();
  const ordered: T[] = [];
  async function visit(node: T): Promise<void> {
    const id = node.manifest.id;
    if (active.has(id)) throw new Error(`插件依赖存在循环：${[...active, id].join(" → ")}`);
    if (done.has(id)) return;
    active.add(id);
    for (const dependency of node.manifest.dependencies) {
      let child = selected.get(dependency.id);
      if (child) {
        await resolve(dependency.id, [dependency.version], child.manifest.version);
      } else {
        child = await resolve(dependency.id, [dependency.version]);
        if (!child || child.manifest.id !== dependency.id) throw new Error(`依赖解析未返回 ${dependency.id}`);
        if (selected.size >= 100) throw new Error("插件依赖超过 100 项，停止安装");
        selected.set(dependency.id, child);
      }
      await visit(child);
    }
    active.delete(id);
    done.add(id);
    ordered.push(node);
  }
  await visit(root);
  return ordered;
}
