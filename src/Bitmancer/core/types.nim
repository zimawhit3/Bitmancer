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
    types/[api, base, cfg, exceptions, loader, ntmmapi, pe, pebteb, shared, sync]
export 
    api, base, cfg, exceptions, loader, ntmmapi, pe, pebteb, shared, sync

type
    ## Distinct pointer for module base addresses.
    ModuleHandle* = distinct pointer

func `==`*(a: ModuleHandle, b: pointer): bool {.borrow.}
func `==`*(a,b: ModuleHandle): bool {.borrow.}
func `isNil`*(a: ModuleHandle): bool {.borrow.}

template `+%`*(h: ModuleHandle, i: SomeInteger): PVOID =
    cast[PVOID](cast[int](h) +% i)

template `-%`*(h: ModuleHandle, i: SomeInteger): PVOID =
    cast[PVOID](cast[int](h) -% i)
