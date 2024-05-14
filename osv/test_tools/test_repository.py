""" Utility class to create a test repository for the git tests

This module contains a class that creates a test repository for the git tests
It can be used to create a test repository and add commits tagged with different
vulnerability types.

usage:
  repo = TestRepository("test_introduced_fixed_linear", debug=False)

  first = repo.add_empty_commit(
        vulnerability=TestRepository.VulnerabilityType.INTRODUCED)
  second = repo.add_empty_commit(parents=[first])
  repo.add_empty_commit(
        parents=[second], vulnerability=TestRepository.VulnerabilityType.FIXED)
"""
import pygit2
import json
from datetime import datetime
from enum import Enum
import os
import shutil
import uuid

class TestRepository:
  """ Utility class to create a test repository for the git tests
  """

  class VulnerabilityType(Enum):
    INTRODUCED = 1
    FIXED = 2
    LAST_AFFECTED = 3
    LIMIT = 4
    NONE = 5


  _author = pygit2.Signature('John Smith', 'johnSmith@example.com')
  _commiter = pygit2.Signature('John Smith', 'johnSmith@example.com')

  def __init__(self, name: str, debug: bool = False):
    self.repo_path=f"osv/testdata/test_repositories/{name}"
    self.debug = debug
    self.name = name
    self.introduced = []
    self.fixed = []
    self.last_affected = []
    self.limit = []
    #delete the repository if it already exists
    if os.path.exists(self.repo_path):
      self.clean()
    #initialize the repository
    self.repo:pygit2._pygit2.Repository = pygit2.init_repository(
        self.repo_path, bare=False)
    #create an initial commit
    parent=[]
    self.add_commit(parent)
    
  def add_commit(self,parents=None):
    if parents is None:
      parents=[self.get_head_hex()]
    with open(f"{self.repo_path}/{ str(uuid.uuid1())}", "w") as f:
      f.write("")
    index = self.repo.index
    index.add_all()
    tree = index.write_tree()
    index.write()
    self.repo.create_commit('HEAD',self._author, self._commiter, "message", tree, parents)
    return self.get_head_hex()
  
  def get_head_hex(self):
    return self.get_head().hex

  def get_head(self):
    return self.repo.revparse_single('HEAD')
  
  def checkout(self,branchname):
    branch = self.repo.lookup_branch(branchname)
    ref = self.repo.lookup_reference(branch.name)
    self.repo.checkout(ref)
    
  def create_branch_if_needed_and_checkout(self,branchname):
    if not self.repo.branches.get(branchname):
      self.repo.create_branch(branchname,self.get_head())
    self.checkout(branchname)

  def create_remote_branch(self):
    for branch_name in self.repo.branches:
      branch=self.repo.branches.get(branch_name)
      self.repo.references.create(f'refs/remotes/origin/{branch_name}', branch.raw_target)

  def add_event_commit(self,event:VulnerabilityType,parents=None):
    self.add_commit(parents)
    match event:
      case self.VulnerabilityType.INTRODUCED:
        self.introduced.append(self.get_head_hex())
      case self.VulnerabilityType.FIXED:
        self.fixed.append(self.get_head_hex())
      case self.VulnerabilityType.LAST_AFFECTED:
        self.last_affected.append(self.get_head_hex())
      case self.VulnerabilityType.LIMIT:
        self.limit.append(self.get_head_hex())
      case self.VulnerabilityType.NONE:
        pass
      case _:
        raise ValueError("Invalid vulnerability type")
    return self.get_head_hex()


  def clean(self):
    shutil.rmtree(self.repo_path)
    ##cleanup
    self.introduced = []
    self.fixed = []
    self.last_affected = []
    self.limit = [] 
    

  def get_ranges(self):
    """
        return the ranges of the repository
        """
    return (self.introduced, self.fixed, self.last_affected, self.limit)

  def print_commits(self):
    """ prints the commits of the repository
    """
    print(self.name)
    commits = []
    for ref in self.repo.listall_reference_objects():
      print(ref.target)
      for commit in self.repo.walk(ref.target, pygit2.GIT_SORT_TIME):

        current_commit = {
            'hash':
                commit.hex,
            'message':
                commit.message,
            'commit_date':
                datetime.utcfromtimestamp(commit.commit_time
                                         ).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'author_name':
                commit.author.name,
            'author_email':
                commit.author.email,
            'parents': [c.hex for c in commit.parents],
        }
        if current_commit in commits:
          break
        commits.append(current_commit)

    print(json.dumps(commits, indent=2))
