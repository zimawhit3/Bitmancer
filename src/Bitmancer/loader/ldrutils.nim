##---------------------------------------------------------------------
##      Bitmancer - a library for Offensive Security Development 
##           
##          Copyright (C) 2022  B. Marshall (zimawhite1@gmail.com)
##
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program.  If not, see <https://www.gnu.org/licenses/>.
## 
##----------------------------------------------------------------------------------
import
    ldrbase

export
    ldrbase

## TODO: Should prbably move these elsewhere...

proc ldrPrepareForwardString*(): NtResult[UNICODE_STRING] =
    var fs = ? new UNICODE_STRING
    fs.addDrivePrefixU()
    fs.addSystem32DirectoryU()
    ok fs

proc ldrResolveApiSet*(apiSetName: cstring): NtResult[UNICODE_STRING] =
    var asn = ? new UNICODE_STRING
    asn.add apiSetName
    ? resolveApiSet(asn, NULL)
    ok asn
