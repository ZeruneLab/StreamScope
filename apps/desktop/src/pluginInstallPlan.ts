type PlanManifest = {
  id: string;
  name: string;
  version: string;
  dependencies: { id: string; version: string }[];
};

// Resolve and validate the complete graph before requesting consent or changing the registry.
export async function planPluginInstallation<T extends { manifest: PlanManifest }>(
  root: T | T[],
  resolve: (id: string, requirements: string[], selectedVersion?: string) => Promise<T | undefined>,
): Promise<T[]> {
  const roots = Array.isArray(root) ? root : [root];
  const selected = new Map<string, T>();
  for (const node of roots) {
    const previous = selected.get(node.manifest.id);
    if (previous && previous.manifest.version !== node.manifest.version) throw new Error(`不能同时选择 ${node.manifest.id} 的多个版本`);
    selected.set(node.manifest.id, node);
  }
  if (selected.size > 100) throw new Error("插件依赖超过 100 项，停止安装");
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
  for (const node of selected.values()) await visit(node);
  return ordered;
}
