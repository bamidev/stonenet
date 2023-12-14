// FIXME: Remove when going stable:
#![allow(dead_code)]

use std::{
	cmp::PartialEq,
	collections::{vec_deque::Iter, VecDeque},
	ops::{Deref, DerefMut},
};

pub struct LimitedVec<V> {
	store: VecDeque<V>,
	limit: usize,
}

pub struct LimitedMap<K, V> {
	base: LimitedVec<(K, V)>,
}

impl<V> LimitedVec<V> {
	pub fn new(limit: usize) -> Self {
		debug_assert!(limit > 0, "Can't use a limit smaller than 1");
		Self {
			store: VecDeque::new(),
			limit,
		}
	}

	pub fn has_space(&self) -> bool { self.store.len() < self.limit }

	pub fn limit(&self) -> usize { self.limit }

	/// Adds a value to the top of the queue, removing anything to stay within
	/// the limit.
	pub fn push_front(&mut self, value: V) {
		while self.store.len() >= self.limit {
			self.store.pop_back();
		}
		self.store.push_front(value);
	}

	/// Adds a value to the bottom of the queue, removing anything to stay
	/// within the limit.
	pub fn push_back(&mut self, value: V) {
		while self.store.len() >= self.limit {
			self.store.pop_front();
		}
		self.store.push_back(value);
	}
}

impl<V> LimitedVec<V>
where
	V: PartialEq,
{
	pub fn contains(&self, value: &V) -> bool {
		for i in self.store.iter() {
			if i == value {
				return true;
			}
		}
		false
	}
}

impl<K, V> LimitedMap<K, V>
where
	K: PartialEq,
{
	pub fn new(limit: usize) -> Self {
		Self {
			base: LimitedVec::new(limit),
		}
	}

	pub fn add(&mut self, key: K, value: V) -> bool {
		match self.index_of(&key) {
			None => {
				self.base.store.push_front((key, value));
				true
			}
			// If key already exists, simply move it forward:
			Some(i) => {
				// FIXME: Make this more efficient
				self.base.store.remove(i);
				self.base.store.push_front((key, value));
				false
			}
		}
	}

	pub fn contains_key(&self, key: &K) -> bool { self.index_of(key).is_some() }

	pub fn index_of(&self, key: &K) -> Option<usize> {
		for i in 0..self.base.store.len() {
			if self.base.store[i].0 == *key {
				return Some(i);
			}
		}
		None
	}

	pub fn insert(&mut self, key: K, value: V) { self.base.push_front((key, value)) }

	pub fn iter(&self) -> Iter<'_, (K, V)> { self.base.store.iter() }

	pub fn find<'a>(&'a self, key: &K) -> Option<&'a V> {
		for entry in self.base.store.iter() {
			if entry.0 == *key {
				return Some(&entry.1);
			}
		}
		None
	}

	pub fn find_mut<'a>(&'a mut self, key: &K) -> Option<&'a mut V> {
		for entry in self.base.store.iter_mut() {
			if entry.0 == *key {
				return Some(&mut entry.1);
			}
		}
		None
	}
}

impl<V> Deref for LimitedVec<V> {
	type Target = VecDeque<V>;

	fn deref(&self) -> &Self::Target { &self.store }
}

impl<V> DerefMut for LimitedVec<V> {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.store }
}

impl<V> Into<Vec<V>> for LimitedVec<V> {
	fn into(self) -> Vec<V> { self.store.into() }
}
