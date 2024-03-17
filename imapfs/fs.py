# IMAPFS - Cloud storage via IMAP
# Copyright (C) 2013 Wes Weber
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import stat
import traceback
import uuid
from collections.abc import Generator

import fuse

from imapfs import directory, file, imapconnection, message


ROOT = str(uuid.UUID(int=0))

fuse.fuse_python_api = (0, 2)


FileOrDir = file.File | directory.Directory
Errno = int | None


class IMAPFS(fuse.Fuse):
  """FUSE object for imapfs
  """

  def __init__(self, *args, **kwargs):
    fuse.Fuse.__init__(self, *args, **kwargs)
    self.open_nodes: dict[str, FileOrDir] = {}

    self.key = ""
    self.rounds = 10000
    self.port = 993
    self.host = "localhost"
    self.user = ""
    self.password = ""
    self.mailbox = ""

  def main(self, args=None):
    # Set up imap
    """Sets up IMAP connection and encryption
    """
    self.imap = imapconnection.IMAPConnection(self.host, int(self.port))
    self.imap.login(self.user, self.password)
    self.imap.select(self.mailbox)

    # Test
    check = self.check_filesystem()
    if check is None:
      self.init_filesystem()
    elif not check:
      raise Exception("Incorrect encryption key")

    # Run
    fuse.Fuse.main(self, args)

    # Close all open nodes
    for node in list(self.open_nodes.values()):
      self.close_node(node)

    # Stop
    self.imap.logout()

  def open_node(self, name: str) -> FileOrDir | None:
    """Opens a node (file or directory)
    """

    # Check cache
    if name in self.open_nodes:
      return self.open_nodes[name]

    try:
      msg = message.Message.open(self.imap, name)
      if not msg:
        return None
    except Exception:
      traceback.print_exc()
      return None

    # Determine file or dir
    type_code = chr(msg.data[0])

    if type_code == 'f':
      obj: FileOrDir = file.File.from_message(msg)
    elif type_code == 'd':
      obj = directory.Directory.from_message(msg)
    else:
      raise Exception("Bad node")

    self.open_nodes[name] = obj
    return obj

  def close_node(self, node: FileOrDir) -> None:
    """Close an open node
    """
    node.close()
    if node.message.name in self.open_nodes:
      self.open_nodes.pop(node.message.name)

  def check_filesystem(self) -> bool | None:
    """Check if there is a filesystem present
    Returns True, False or None
    Returns True when a filesystem is successfully located
    Returns False when a filesystem is present, but cannot be decrypted
    Returns None when no filesystem is found
    """
    try:
      root = self.open_node(ROOT)
    except Exception:
      traceback.print_exc()
      return False

    if root is None:
      return None

    if not isinstance(root, directory.Directory):
      return False

    # check if decrypted properly
    data = bytes(root.message.data[0:3])
    if data != b"d\r\n":
      return False

    return True

  def init_filesystem(self) -> None:
    """Create a filesystem
    """
    root = directory.Directory.create(self.imap)
    root.message.name = ROOT
    root.close()

  def get_node_by_path(self, path: str) -> FileOrDir | None:
    """Open the node specified by path
    Walks through the directory tree to find the node
    """
    # handle root
    if path == "/":
      return self.open_node(ROOT)

    # split into directory parts
    parts = path.split("/")
    current_node = self.open_node(ROOT)
    for part in parts:
      if not part:  # blank entry from double slashes
        continue

      # Trying to get the child of a file?
      if not isinstance(current_node, directory.Directory):
        break

      # find children
      child_key = current_node.get_child_by_name(part)
      if not child_key:
        return None

      # Open child, then set it to be searched
      child_node = self.open_node(child_key)
      if not child_node:
        return None
      current_node = child_node
    return current_node

  def get_path_parent(self, path: str) -> str:
    """Gets the parent part of a path
    """
    parts = path.rpartition("/")
    return parts[0]

  def get_path_filename(self, path: str) -> str:
    """Gets the filename part of a path
    """
    parts = path.rpartition("/")
    return parts[2]

  #
  # Filesystem functions
  #

  def statfs(self) -> fuse.StatVfs:
    st = fuse.StatVfs()
    st.f_bsize = file.FS_BLOCK_SIZE
    st.f_frsize = file.FS_BLOCK_SIZE

    return st

  def getattr(self, path: str) -> fuse.Stat | int:
    node = self.get_node_by_path(path)

    if not node:
      return -fuse.ENOENT

    st = fuse.Stat()

    if isinstance(node, directory.Directory):
      st.st_mode = stat.S_IFDIR | 0o777
      st.st_nlink = 2
      st.st_size = 4096
    else:
      st.st_mode = stat.S_IFREG | 0o666
      st.st_nlink = 1
      st.st_size = node.size

    return st

  def readdir(self, path: str, offset) -> Generator[fuse.Direntry, None, None]:
    node = self.get_node_by_path(path)
    if not isinstance(node, directory.Directory):
      return

    logging.debug("Listing %s/", path)

    yield fuse.Direntry(".")
    yield fuse.Direntry("..")

    for child_name in node.children.values():
      yield fuse.Direntry(child_name)

  def mkdir(self, path: str, mode) -> Errno:
    parent = self.get_node_by_path(self.get_path_parent(path))
    if not parent:
      return -fuse.ENOENT

    assert isinstance(parent, directory.Directory)

    if parent.get_child_by_name(self.get_path_filename(path)):
      return -fuse.EEXIST

    logging.debug("Creating directory %s/", path)

    child = directory.Directory.create(self.imap)
    self.open_nodes[child.message.name] = child
    parent.add_child(child.message.name, self.get_path_filename(path))

  def rmdir(self, path: str) -> Errno:
    child = self.get_node_by_path(path)
    if not child:
      return -fuse.ENOENT

    if not isinstance(child, directory.Directory):
      return -fuse.ENOTDIR

    if len(child.children) > 0:
      return -fuse.ENOTEMPTY

    parent = self.get_node_by_path(self.get_path_parent(path))
    if not parent:
      return -fuse.ENOENT

    logging.debug("Removing directory %s/", path)

    assert isinstance(parent, directory.Directory)

    parent.remove_child(child.message.name)
    self.close_node(child)
    message.Message.unlink(self.imap, child.message.name)

  def mknod(self, path: str, mode, dev) -> Errno:
    parent = self.get_node_by_path(self.get_path_parent(path))
    if not parent:
      return -fuse.ENOENT

    assert isinstance(parent, directory.Directory)

    if parent.get_child_by_name(self.get_path_filename(path)):
      return -fuse.EEXIST

    logging.debug("Creating file %s", path)

    node = file.File.create(self.imap)
    self.open_nodes[node.message.name] = node
    parent.add_child(node.message.name, self.get_path_filename(path))

  def rename(self, oldpath: str, newpath: str) -> Errno:
    # handle dir name
    if not self.get_path_filename(newpath):
      newpath += self.get_path_filename(oldpath)

    logging.debug("Moving %s to %s", oldpath, newpath)

    # handle same-parent
    if self.get_path_parent(oldpath) == self.get_path_parent(newpath):
      parent = self.get_node_by_path(self.get_path_parent(oldpath))
      if not parent:
        return -fuse.ENOENT

      assert isinstance(parent, directory.Directory)

      # For simplicity we do not allow overwriting
      new_child_key = parent.get_child_by_name(self.get_path_filename(newpath))
      if new_child_key:
        return -fuse.EEXIST

      child_key = parent.get_child_by_name(self.get_path_filename(oldpath))
      assert child_key
      parent.children[child_key] = self.get_path_filename(newpath)
      parent.dirty = True
    else:
      # Different parent
      old_node = self.get_node_by_path(oldpath)
      if not old_node:
        return -fuse.ENOENT
      old_parent = self.get_node_by_path(self.get_path_parent(oldpath))
      if not old_parent:
        return -fuse.ENOENT

      # For simplicity we do not allow overwriting
      new_node = self.get_node_by_path(newpath)
      if new_node:
        return -fuse.EEXIST

      new_parent = self.get_node_by_path(self.get_path_parent(newpath))

      assert isinstance(old_parent, directory.Directory)
      assert isinstance(new_parent, directory.Directory)

      # Remove old, add new
      new_parent.add_child(old_node.message.name, self.get_path_filename(oldpath))
      old_parent.remove_child(old_node.message.name)

  def utime(self, path: str, times) -> Errno:
    node = self.get_node_by_path(path)
    if not node:
      return -fuse.ENOENT

    node.mtime = times[1]
    node.dirty = True

  def unlink(self, path: str) -> Errno:
    node = self.get_node_by_path(path)
    if not node or not isinstance(node, file.File):
      return -fuse.ENOENT

    parent = self.get_node_by_path(self.get_path_parent(path))
    if not parent:
      return -fuse.ENOENT

    logging.debug("Removing %s", path)
    assert isinstance(parent, directory.Directory)

    parent.remove_child(node.message.name)
    node.delete()
    self.open_nodes.pop(node.message.name)

  def truncate(self, path: str, size: int) -> Errno:
    node = self.get_node_by_path(path)
    if not node:
      return -fuse.ENOENT

    if not isinstance(node, file.File):
      return -fuse.EISDIR

    logging.debug("Resizing %s to %d", path, size)

    node.truncate(size)

  def read(self, path: str, size: int, offset: int) -> bytes | Errno:
    node = self.get_node_by_path(path)
    if not node:
      return -fuse.ENOENT
    if not isinstance(node, file.File):
      return -fuse.EISDIR

    node.seek(offset)
    data = bytes(node.read(size))

    logging.debug("Read %d-%d returned %d bytes", offset, size + offset, len(data))

    return data

  def write(self, path: str, buf: bytes, offset: int) -> int:
    node = self.get_node_by_path(path)
    if not node:
      return -fuse.ENOENT
    if not isinstance(node, file.File):
      return -fuse.EISDIR

    byte_buf = bytearray(buf)

    node.seek(offset)
    node.write(byte_buf)

    logging.debug("Write %d-%d", offset, offset + len(buf))

    return len(buf)

  def release(self, path: str, flags) -> Errno:
    node = self.get_node_by_path(path)
    if not node:
      return -fuse.ENOENT

    logging.debug("Closing %s", path)
    assert isinstance(node, file.File)

    node.close_blocks()

    node.flush()

  def releasedir(self, path: str) -> Errno:
    node = self.get_node_by_path(path)
    if not node:
      return -fuse.ENOENT

    logging.debug("Closing %s/", path)
    assert isinstance(node, directory.Directory)

    node.flush()

  def chmod(self, path: str, mode) -> Errno:
    return 0

  def chown(self, path: str, user, group) -> Errno:
    return 0
