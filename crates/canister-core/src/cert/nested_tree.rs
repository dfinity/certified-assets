use ic_certification::{AsHashTree, HashTree, RbTree};

pub trait NestedTreeKeyRequirements: Clone + AsRef<[u8]> + 'static {}
pub trait NestedTreeValueRequirements: AsHashTree + 'static {}
impl<T> NestedTreeKeyRequirements for T where T: Clone + AsRef<[u8]> + 'static {}
impl<T> NestedTreeValueRequirements for T where T: AsHashTree + 'static {}

#[derive(Debug, Clone)]
pub enum NestedTree<K: NestedTreeKeyRequirements, V: NestedTreeValueRequirements> {
    Leaf(V),
    Nested(RbTree<K, NestedTree<K, V>>),
}

impl<K: NestedTreeKeyRequirements, V: NestedTreeValueRequirements> Default for NestedTree<K, V> {
    fn default() -> Self {
        NestedTree::Nested(RbTree::<K, NestedTree<K, V>>::new())
    }
}

impl<K: NestedTreeKeyRequirements, V: NestedTreeValueRequirements> AsHashTree for NestedTree<K, V> {
    fn root_hash(&self) -> ic_certification::Hash {
        match self {
            NestedTree::Leaf(a) => a.root_hash(),
            NestedTree::Nested(tree) => tree.root_hash(),
        }
    }

    fn as_hash_tree(&self) -> HashTree {
        match self {
            NestedTree::Leaf(a) => a.as_hash_tree(),
            NestedTree::Nested(tree) => tree.as_hash_tree(),
        }
    }
}

impl<K: NestedTreeKeyRequirements, V: NestedTreeValueRequirements> NestedTree<K, V> {
    #[allow(dead_code)]
    pub fn get(&self, path: &[K]) -> Option<&V> {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(_) => None,
                NestedTree::Nested(tree) => tree
                    .get(key.as_ref())
                    .and_then(|child| child.get(&path[1..])),
            }
        } else {
            match self {
                NestedTree::Leaf(value) => Some(value),
                NestedTree::Nested(_) => None,
            }
        }
    }

    /// Returns true if there is a leaf at the specified path
    pub fn contains_leaf(&self, path: &[K]) -> bool {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(_) => false,
                NestedTree::Nested(tree) => tree
                    .get(key.as_ref())
                    .map(|child| child.contains_leaf(&path[1..]))
                    .unwrap_or(false),
            }
        } else {
            matches!(self, NestedTree::Leaf(_))
        }
    }

    /// Returns true if there is a leaf or a subtree at the specified path
    pub fn contains_path(&self, path: &[K]) -> bool {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(_) => false,
                NestedTree::Nested(tree) => tree
                    .get(key.as_ref())
                    .map(|child| child.contains_path(&path[1..]))
                    .unwrap_or(false),
            }
        } else {
            true
        }
    }

    pub fn insert(&mut self, path: &[K], value: V) {
        let Some(key) = path.first() else {
            *self = NestedTree::Leaf(value);
            return;
        };
        match self {
            NestedTree::Leaf(_) => {
                *self = NestedTree::default();
                self.insert(path, value);
            }
            NestedTree::Nested(tree) => {
                if tree.get(key.as_ref()).is_some() {
                    tree.modify(key.as_ref(), |child| child.insert(&path[1..], value));
                } else {
                    // Build the new branch off-tree and link it with a single
                    // insert: every insert or modify rehashes its path through
                    // this level, so linking an empty child first and then
                    // filling it would hash the path twice.
                    let mut child = NestedTree::default();
                    child.insert(&path[1..], value);
                    tree.insert(key.clone(), child);
                }
            }
        }
    }

    /// Deletes the leaf or subtree at `path`, unlinking every ancestor the
    /// deletion leaves empty. A no-op (and, unlike a blind `modify`, free of
    /// rehashing) if nothing is at `path`.
    ///
    /// Empty ancestors must go: an orphan path is read by the v2 HTTP gateway's
    /// response verifier as "a more-specific Exact expression path might exist
    /// for this URL", and it rejects wildcard `<*>` responses with 503.
    pub fn delete(&mut self, path: &[K]) {
        if self.contains_path(path) {
            self.delete_present(path);
        }
    }

    /// [`Self::delete`] for a `path` known to be present. Unlinks the topmost
    /// ancestor the deletion would leave empty in one step, rather than
    /// emptying it and pruning on the way back up (which rehashes every level
    /// twice).
    fn delete_present(&mut self, path: &[K]) {
        let Some(key) = path.first() else {
            *self = NestedTree::default();
            return;
        };
        let NestedTree::Nested(tree) = self else {
            return;
        };
        if tree
            .get(key.as_ref())
            .is_some_and(|child| child.empties_on_delete(&path[1..]))
        {
            tree.delete(key.as_ref());
        } else {
            tree.modify(key.as_ref(), |child| child.delete_present(&path[1..]));
        }
    }

    /// Whether deleting `path` (known present) leaves `self` with nothing in
    /// it: every level down to `path`'s end holds that one branch only.
    fn empties_on_delete(&self, path: &[K]) -> bool {
        let Some(key) = path.first() else {
            return true;
        };
        match self {
            NestedTree::Leaf(_) => false,
            NestedTree::Nested(tree) => {
                let mut entries = tree.iter();
                match (entries.next(), entries.next()) {
                    (Some((k, child)), None) => {
                        k.as_ref() == key.as_ref() && child.empties_on_delete(&path[1..])
                    }
                    _ => false,
                }
            }
        }
    }

    /// Every leaf's path, in key order.
    #[cfg(test)]
    pub fn leaf_paths(&self) -> Vec<Vec<K>> {
        let mut out = Vec::new();
        self.collect_leaf_paths(&mut Vec::new(), &mut out);
        out
    }

    #[cfg(test)]
    fn collect_leaf_paths(&self, prefix: &mut Vec<K>, out: &mut Vec<Vec<K>>) {
        match self {
            NestedTree::Leaf(_) => out.push(prefix.clone()),
            NestedTree::Nested(tree) => {
                for (key, child) in tree.iter() {
                    prefix.push(key.clone());
                    child.collect_leaf_paths(prefix, out);
                    prefix.pop();
                }
            }
        }
    }

    pub fn witness(&self, path: &[K]) -> HashTree {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(value) => value.as_hash_tree(),
                NestedTree::Nested(tree) => {
                    tree.nested_witness(key.as_ref(), |tree| tree.witness(&path[1..]))
                }
            }
        } else {
            self.as_hash_tree()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_tree_operation() {
        let mut tree: NestedTree<&str, Vec<u8>> = NestedTree::default();
        // insertion
        tree.insert(&["one", "two"], vec![2]);
        tree.insert(&["one", "three"], vec![3]);
        assert_eq!(tree.get(&["one", "two"]), Some(&vec![2]));
        assert_eq!(tree.get(&["one", "two", "three"]), None);
        assert_eq!(tree.get(&["one"]), None);
        assert!(tree.contains_leaf(&["one", "two"]));
        assert!(tree.contains_path(&["one"]));
        assert!(!tree.contains_leaf(&["one", "two", "three"]));
        assert!(!tree.contains_path(&["one", "two", "three"]));
        assert!(!tree.contains_leaf(&["one"]));

        // deleting non-existent key doesn't do anything
        tree.delete(&["one", "two", "three"]);
        assert_eq!(tree.get(&["one", "two"]), Some(&vec![2]));
        assert!(tree.contains_leaf(&["one", "two"]));

        // deleting existing key works
        tree.delete(&["one", "three"]);
        assert_eq!(tree.get(&["one", "two"]), Some(&vec![2]));
        assert_eq!(tree.get(&["one", "three"]), None);
        assert!(tree.contains_leaf(&["one", "two"]));
        assert!(!tree.contains_leaf(&["one", "three"]));

        // deleting subtree works
        tree.delete(&["one"]);
        assert_eq!(tree.get(&["one", "two"]), None);
        assert_eq!(tree.get(&["one"]), None);
        assert!(!tree.contains_leaf(&["one", "two"]));
        assert!(!tree.contains_leaf(&["one"]));
    }

    #[test]
    fn delete_prunes_empty_parent_chain() {
        // Deleting a deeply-nested leaf must unlink every now-empty ancestor.
        // Otherwise `contains_path` for the deleted leaf's parents still returns
        // true (the empty `Nested` subtrees count as "the path exists"), and
        // the HTTP gateway's response verifier rejects wildcard responses
        // because a "potential exact expression path" is visible at the
        // orphaned path.
        let mut tree: NestedTree<&str, Vec<u8>> = NestedTree::default();
        tree.insert(&["a", "b", "c"], vec![1]);
        assert!(tree.contains_path(&["a", "b", "c"]));
        assert!(tree.contains_path(&["a", "b"]));
        assert!(tree.contains_path(&["a"]));

        tree.delete(&["a", "b", "c"]);
        // Every ancestor that has no remaining content must be unlinked.
        assert!(!tree.contains_path(&["a", "b", "c"]));
        assert!(!tree.contains_path(&["a", "b"]));
        assert!(!tree.contains_path(&["a"]));
    }

    #[test]
    fn delete_preserves_siblings_in_ancestor_chain() {
        // Pruning must stop at the first ancestor that still has other
        // children — we don't want to collapse the whole tree just because
        // one leaf went away.
        let mut tree: NestedTree<&str, Vec<u8>> = NestedTree::default();
        tree.insert(&["a", "b", "c"], vec![1]);
        tree.insert(&["a", "x"], vec![2]);

        tree.delete(&["a", "b", "c"]);
        // "a" still has "x" so the chain stops there.
        assert!(!tree.contains_path(&["a", "b"]));
        assert!(tree.contains_path(&["a"]));
        assert_eq!(tree.get(&["a", "x"]), Some(&vec![2]));
    }
}
