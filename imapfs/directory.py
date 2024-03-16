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

import time
from typing import Self

from imapfs import message
from imapfs.imapconnection import IMAPConnection


class Directory:
  """Represents a directory
  Contains a list of file names
  """

  def __init__(self, msg: message.Message, ctime: float, mtime: float, children: dict[str, str]):
    self.message = msg
    self.ctime = ctime
    self.mtime = mtime
    self.children = children
    self.dirty = False

  def add_child(self, key: str, name: str) -> None:
    """Add a child to this directory
    """
    self.children[key] = name
    self.dirty = True

  def remove_child(self, key: str) -> None:
    """Remove a child by key from this dir
    """
    if key not in self.children:
      return
    self.children.pop(key)
    self.dirty = True

  def get_child_by_name(self, name: str) -> str | None:
    """Get a child's key by its name
    """
    for child_key, child_name in self.children.items():
      if child_name == name:
        return child_key
    return None

  def flush(self) -> None:
    """Writes the changes to the server
    """
    if self.dirty:
      self.mtime = time.time()
      self.message.truncate(0)  # clear
      self.message.write(b"d\r\n%d\t%d\r\n" % (self.ctime, self.mtime))
      for child_key, child_name in self.children.items():
        self.message.write(b"%s\t%s\r\n" % (child_key.encode(), child_name.encode()))
      self.message.flush()
      self.dirty = False

  def close(self) -> None:
    """Close
    Calls flush
    """
    self.flush()
    self.message.close()

  @classmethod
  def create(cls, conn: IMAPConnection) -> Self:
    """Create a directory
    """
    msg = message.Message.create(conn)
    d = cls(msg, time.time(), time.time(), {})
    d.dirty = True
    return d

  @classmethod
  def from_message(cls, msg: message.Message) -> Self:
    """Create a directory object from a message
    """
    data = bytes(msg.read()).decode()

    lines = data.split("\r\n")
    info = lines[1].split("\t")

    children = {}
    for line in lines[2:]:
      if not line:
        continue
      line_info = line.split("\t")
      children[line_info[0]] = line_info[1]

    d = cls(msg, int(info[0]), int(info[1]), children)
    return d
