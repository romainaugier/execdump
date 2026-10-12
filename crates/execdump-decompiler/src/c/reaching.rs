/*
 * Reaching conditions: the condition under which the control reaches a block from the start of a
 * region, from the branch conditions along the paths to it (the disjunction of the conjunctions of
 * the conditions of each path). They are kept small (absorption, a && b || a && !b is a) and are
 * printed factored (the literals shared by several paths first), as the guard of the block.
 */

use super::ast::{BinaryOp, Expr};

/// The cubes of a condition stop being tracked past this count (the condition is then unknown)
const MAX_CUBES: usize = 32;

/// An atom (a branch condition, or a case of a switch) or its negation
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lit {
    pub atom: usize,
    pub positive: bool,
}

/// Conjunction of literals, sorted by atom, at most one per atom
pub type Cube = Vec<Lit>;

/// The atoms: their expression (when true), and for the cases of a switch the switch they belong
/// to (two cases of a switch are never true together)
#[derive(Default)]
pub struct Atoms {
    pub exprs: Vec<Expr>,
    pub switch: Vec<Option<usize>>,
}

impl Atoms {
    pub fn add(&mut self, expr: Expr, switch: Option<usize>) -> usize {
        self.exprs.push(expr);
        self.switch.push(switch);
        return self.exprs.len() - 1;
    }

    fn lit(&self, lit: Lit) -> Expr {
        let expr = self.exprs[lit.atom].clone();
        return if lit.positive { expr } else { expr.not() };
    }
}

/// Disjunction of cubes: none is false, an empty cube is true
#[derive(Clone, Debug, PartialEq)]
pub struct Cond {
    pub cubes: Vec<Cube>,
}

impl Cond {
    pub fn truth() -> Cond {
        return Cond { cubes: vec![Vec::new()] };
    }

    pub fn falsity() -> Cond {
        return Cond { cubes: Vec::new() };
    }

    pub fn lit(atom: usize, positive: bool) -> Cond {
        return Cond { cubes: vec![vec![Lit { atom, positive }]] };
    }

    /// Conjunction, None when it has too many cubes
    pub fn and(&self, other: &Cond, atoms: &Atoms) -> Option<Cond> {
        let mut cubes = Vec::new();

        for a in self.cubes.iter() {
            for b in other.cubes.iter() {
                if let Some(cube) = conjunction(a, b, atoms) {
                    cubes.push(cube);
                }
            }
        }

        return Cond { cubes }.simplified();
    }

    /// Disjunction, None when it has too many cubes
    pub fn or(&self, other: &Cond) -> Option<Cond> {
        let mut cubes = self.cubes.clone();
        cubes.extend(other.cubes.iter().cloned());
        return Cond { cubes }.simplified();
    }

    fn simplified(mut self) -> Option<Cond> {
        loop {
            self.cubes.sort();
            self.cubes.dedup();

            // Absorption: a || a && b is a
            let cubes = self.cubes.clone();
            self.cubes.retain(|c| !cubes.iter().any(|d| d != c && d.iter().all(|l| c.contains(l))));

            // a && x || a && !x is a
            let mut merged = None;

            'search: for (i, a) in self.cubes.iter().enumerate() {
                for b in self.cubes[i + 1..].iter() {
                    if a.len() != b.len() {
                        continue;
                    }

                    let differ: Vec<usize> = (0..a.len()).filter(|&k| a[k] != b[k]).collect();

                    if let [k] = differ[..] {
                        if a[k].atom == b[k].atom {
                            let mut cube = a.clone();
                            cube.remove(k);
                            merged = Some(cube);
                            break 'search;
                        }
                    }
                }
            }

            if let Some(cube) = merged {
                self.cubes.push(cube);
                continue;
            }

            // a || !a && b is a || b (more generally: the cube with !a loses it when the rest of the
            // cube with a is in it)
            let mut reduced = None;

            'reduce: for p in self.cubes.iter() {
                for (j, q) in self.cubes.iter().enumerate() {
                    for (k, lit) in q.iter().enumerate() {
                        let opposite = Lit { atom: lit.atom, positive: !lit.positive };

                        if p.contains(&opposite) && p.iter().all(|l| *l == opposite || q.contains(l)) {
                            reduced = Some((j, k));
                            break 'reduce;
                        }
                    }
                }
            }

            match reduced {
                Some((j, k)) => {
                    self.cubes[j].remove(k);
                }
                None => break,
            }
        }

        return (self.cubes.len() <= MAX_CUBES).then_some(self);
    }

    /// Atoms the condition uses
    pub fn atoms(&self) -> Vec<usize> {
        let mut atoms: Vec<usize> = self.cubes.iter().flatten().map(|l| l.atom).collect();
        atoms.sort();
        atoms.dedup();
        return atoms;
    }

    /// The condition as an expression (the atoms in the order of their blocks) and its number of literals
    pub fn expr(&self, atoms: &Atoms) -> (Expr, usize) {
        return factored(&self.cubes, atoms);
    }
}

/// Conjunction of two cubes, None when it is false
fn conjunction(a: &Cube, b: &Cube, atoms: &Atoms) -> Option<Cube> {
    let mut cube = a.clone();

    for &lit in b.iter() {
        match cube.iter().find(|l| l.atom == lit.atom) {
            Some(l) if l.positive != lit.positive => return None,
            Some(_) => {}
            None => cube.push(lit),
        }
    }

    // A case of a switch is true: the other cases of the switch are false
    let cases: Vec<(usize, usize)> = cube.iter().filter(|l| l.positive).filter_map(|l| Some((atoms.switch[l.atom]?, l.atom))).collect();

    for (i, &(switch, atom)) in cases.iter().enumerate() {
        if cases[i + 1..].iter().any(|&(s, a)| s == switch && a != atom) {
            return None;
        }

        cube.retain(|l| l.positive || atoms.switch[l.atom] != Some(switch));
    }

    cube.sort();
    return Some(cube);
}

fn and(a: Expr, b: Expr) -> Expr {
    return Expr::binary(BinaryOp::LogicalAnd, a, b);
}

fn or(a: Expr, b: Expr) -> Expr {
    return Expr::binary(BinaryOp::LogicalOr, a, b);
}

/// Disjunction of the cubes, the literals shared by several cubes factored out
fn factored(cubes: &[Cube], atoms: &Atoms) -> (Expr, usize) {
    if cubes.is_empty() {
        return (Expr::Int(0), 0);
    }

    if cubes.iter().any(|c| c.is_empty()) {
        return (Expr::Int(1), 0);
    }

    // The literal most cubes have (the first block's on ties)
    let mut lits: Vec<Lit> = cubes.iter().flatten().copied().collect();
    lits.sort();
    lits.dedup();

    let best = lits.iter().copied().max_by_key(|l| (cubes.iter().filter(|c| c.contains(l)).count(), std::cmp::Reverse(*l))).unwrap();
    let with: Vec<Cube> = cubes.iter().filter(|c| c.contains(&best)).map(|c| c.iter().copied().filter(|l| *l != best).collect()).collect();
    let without: Vec<Cube> = cubes.iter().filter(|c| !c.contains(&best)).cloned().collect();

    let (rest, n) = factored(&with, atoms);
    let (term, count) = match rest {
        Expr::Int(1) => (atoms.lit(best), 1),
        rest => (and(atoms.lit(best), rest), n + 1),
    };

    if without.is_empty() {
        return (term, count);
    }

    let (others, m) = factored(&without, atoms);
    return (or(term, others), count + m);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atoms(n: usize) -> Atoms {
        let mut atoms = Atoms::default();

        for i in 0..n {
            atoms.add(Expr::Name(format!("c{}", i)), None);
        }

        return atoms;
    }

    #[test]
    fn simplification() {
        let atoms = atoms(3);
        let a = Cond::lit(0, true);
        let b = Cond::lit(1, true);

        // a && b || a && !b is a
        let left = a.and(&b, &atoms).unwrap();
        let right = a.and(&Cond::lit(1, false), &atoms).unwrap();
        assert_eq!(left.or(&right).unwrap(), a);

        // a || !a && b is a || b
        let c = Cond::lit(2, true);
        let not_a_and_c = Cond::lit(0, false).and(&c, &atoms).unwrap();
        assert_eq!(a.or(&not_a_and_c).unwrap(), a.or(&c).unwrap());

        // a || a && b is a, a && !a is false
        assert_eq!(a.or(&left).unwrap(), a);
        assert_eq!(a.and(&Cond::lit(0, false), &atoms).unwrap(), Cond::falsity());
    }

    #[test]
    fn switch_cases_exclude_each_other() {
        let mut atoms = Atoms::default();
        atoms.add(Expr::Name("x1".into()), Some(0));
        atoms.add(Expr::Name("x2".into()), Some(0));

        let one = Cond::lit(0, true);
        assert_eq!(one.and(&Cond::lit(1, true), &atoms).unwrap(), Cond::falsity());
        assert_eq!(one.and(&Cond::lit(1, false), &atoms).unwrap(), one);
    }

    #[test]
    fn factoring() {
        let atoms = atoms(3);
        let cond = Cond::lit(0, true).and(&Cond::lit(1, true), &atoms).unwrap().or(&Cond::lit(0, true).and(&Cond::lit(2, true), &atoms).unwrap()).unwrap();
        let (expr, count) = cond.expr(&atoms);

        assert_eq!(count, 3);
        assert_eq!(expr, and(Expr::Name("c0".into()), or(Expr::Name("c1".into()), Expr::Name("c2".into()))));
    }
}
