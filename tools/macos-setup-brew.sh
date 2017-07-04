#!/bin/sh
# Copyright 2014, Evan Huus (See AUTHORS file)
#
# Enhance (2016) by Alexis La Goutte (For use with Travis CI)
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#Update to last brew release
brew update

brew upgrade

#install some libs needed by Wireshark
brew install c-ares glib libgcrypt gnutls lua cmake nghttp2 snappy lz4 libxml2 asciidoc

#install Qt5
brew install qt5

echo "You need to add Qt on PATH via

PATH=/usr/local/opt/qt/bin:\$PATH
or (to be permanent)
echo 'export PATH=/usr/local/opt/qt/bin:\$PATH' >> ~/.bash_profile"

#Fix qt5 lib link
brew link --force qt5
#VERSION=`brew info qt5 | grep /usr/local/Cellar | tail -n 1 | cut -d '/' -f6 | cut -d ' ' -f1`
#sudo rm /usr/local/mkspecs /usr/local/plugins
#sudo ln -s /usr/local/Cellar/qt/$VERSION/mkspecs /usr/local/
#sudo ln -s /usr/local/Cellar/qt/$VERSION/plugins /usr/local/

#
#  Editor modelines
#
#  Local Variables:
#  c-basic-offset: 4
#  tab-width: 8
#  indent-tabs-mode: nil
#  End:
#
#  ex: set shiftwidth=4 tabstop=8 expandtab:
#  :indentSize=4:tabSize=8:noTabs=true:
#
