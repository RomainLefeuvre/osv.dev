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
class EventType(Enum):
    INTRODUCED = 1
    FIXED = 2
    LAST_AFFECTED = 3
    LIMIT = 4
    NONE = 5

class CommitInfo:
    def __init__(self,commit_id:str,commit_message:str,vulnerability_type:EventType):
      self.commit_id: str = commit_id
      self.commit_message: str = commit_message
      self.vulnerability_type:EventType = vulnerability_type
  
class CommitsInfo:
    def __init__(self):
      self._commits :list[CommitInfo]= []

    def existing_message(self,message):
      for commit in self._commits:
        if commit.commit_message==message:
          return True
      return False  
    
    def add_commit(self,commit_id,commit_message,vulnerability_type=EventType.NONE):
      if not self.existing_message(commit_message):
        self._commits.append(CommitInfo(commit_id,commit_message,vulnerability_type))
      else :
        raise ValueError("Commit message already exists")
      
    def get_commit_id_by_message(self,message):
      for commit in self._commits:
        if commit.commit_message==message:
          return commit.commit_id
      return None
    
    def get_commit_ids(self,commit_messages):
      commit_ids = set()
      for commit_message in commit_messages:
        commit_id = self.get_commit_id_by_message(commit_message)
        if commit_id is not None:
          commit_ids.add(commit_id)
      return commit_ids

    def get_ranges(self):
      introduced = []
      fixed = []
      last_affected = []
      limit = []
      for commit in self._commits:
        match commit.vulnerability_type:
          case EventType.INTRODUCED:
            introduced.append(commit.commit_id)
          case EventType.FIXED:
            fixed.append(commit.commit_id)
          case EventType.LAST_AFFECTED:
            last_affected.append(commit.commit_id)
          case EventType.LIMIT:
            limit.append(commit.commit_id)
          case EventType.NONE:
            pass
          case _:
            raise ValueError("Invalid vulnerability type")
      return (introduced, fixed, last_affected, limit)
class TestRepository:
  """ Utility class to create a test repository for the git tests
  """
  _author = pygit2.Signature('John Smith', 'johnSmith@example.com')
  _commiter = pygit2.Signature('John Smith', 'johnSmith@example.com')

  def __init__(self, name: str, debug: bool = False):
    self.repo_path=f"osv/testdata/test_repositories/{name}"
    self.debug = debug
    self.name = name
    self.commits_info = CommitsInfo()
    
    #delete the repository if it already exists
    if os.path.exists(self.repo_path):
      self.clean()
    #initialize the repository
    self.repo:pygit2._pygit2.Repository = pygit2.init_repository(
        self.repo_path, bare=False)
    #create an initial commit
    parent=[]
    self.add_commit(message="A",parents=parent)

  def merge(self,commit,event:EventType=EventType.NONE):
    self.repo.merge(commit)
    self.add_commit([self.get_head_hex(),commit],event)

  def get_commit_ids(self,commit_messages):
    return self.commits_info.get_commit_ids(commit_messages)
  
  def add_commit(self,message,parents=None,event:EventType=EventType.NONE):
    if parents is None:
      parents=[self.get_head_hex()]
    with open(f"{self.repo_path}/{ str(uuid.uuid1())}", "w") as f:
      f.write("")
    index = self.repo.index
    index.add_all()
    tree = index.write_tree()
    index.write()
    commit_hex = self.repo.create_commit('HEAD',self._author, self._commiter, message, tree, parents).hex
    self.commits_info.add_commit(commit_hex,message,event)
    return commit_hex
  
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
    return self.commits_info.get_ranges()

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
