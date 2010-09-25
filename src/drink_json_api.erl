%%%-------------------------------------------------------------------
%%% File    : drink_json_api.erl
%%% Author  : Dan Willemsen <dan@csh.rit.edu>
%%% Purpose : 
%%%
%%%
%%% edrink, Copyright (C) 2008-2010 Dan Willemsen
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%                         
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%-------------------------------------------------------------------

-module (drink_json_api).

-export ([request/3]).
-export ([machine_stat/2, slot_stat/1]).
-export ([format_time/1, encode_event/3]).

-export ([currentuser/1, drop/4, logs/3, machines/1, moduser/5, addslot/7, setslot/7, delslot/3,
          temperatures/3, userinfo/2, addmachine/9, modmachine/9, delmachine/2, getconnections/1,
          addapp/3, getapps/1, delapp/2]).

-include_lib ("drink/include/user.hrl").
-include_lib ("drink/include/drink_mnesia.hrl").
-include_lib ("drink_log/include/drink_log.hrl").
-include_lib ("drink_app_auth/include/app_auth.hrl").

arg(atom, V) when is_atom(V) -> {ok, V};
arg(atom, V) when is_list(V) -> {ok, list_to_atom(V)};
arg(atom, _) -> {error, unknown_conversion};
arg(ip, V) when is_tuple(V) -> {ok, V};
arg(ip, V) when is_list(V) -> inet:getaddr(V, inet);
arg(ip, _) -> {error, unknown_conversion};
arg(boolean, true) -> {ok, true};
arg(boolean, false) -> {ok, false};
arg(boolean, V) when is_atom(V) -> {error, unknown_boolean};
arg(boolean, V) when is_list(V) -> arg(boolean, list_to_atom(V));
arg(boolean, _) -> {error, unknown_conversion};
arg(integer, V) when is_integer(V) -> {ok, V};
arg(integer, V) when is_list(V) ->
    case string:to_integer(V) of
        {Int, ""} -> {ok, Int};
        _ -> {error, bad_conversion}
    end;
arg(integer, _) -> {error, unknown_conversion}.

args(_A, []) ->
    [];
args(A, [{H,Type}|T]) ->
    case lists:keyfind(H, 1, A) of
        false -> {error, {arg_missing, H}};
        {H, V} ->
            case arg(Type, V) of
                {ok, Val} -> 
                    case args(A, T) of
                        {error, Reason} -> {error, Reason};
                        Args -> [Val] ++ Args
                    end;
                _ -> {error, {invalid_arg, H}}
            end
    end;
args(A, [{H}|T]) ->
    case lists:keyfind(H, 1, A) of
        false -> {error, {arg_missing, H}};
        {H, V} -> 
            case args(A, T) of
                {error, Reason} -> {error, Reason};
                Args -> [V] ++ Args
            end
    end.

request(U, currentuser, _) ->
    api(U, currentuser, nil, []);
request(U, drop, A) ->
    api(U, drop, A, [{machine, atom},
                     {slot, integer},
                     {delay, integer}]);
request(U, logs, A) ->
    api(U, logs, A, [{offset, integer},
                     {limit, integer}]);
request(U, machines, A) ->
    api(U, machines, A, []);
request(U, moduser, A) ->
    api(U, moduser, A, [{username},
                        {attr, atom},
                        {value},
                        {reason}]);
request(U, addslot, A) ->
    api(U, addslot, A, [{machine, atom},
                        {slot, integer},
                        {name},
                        {price, integer},
                        {available, integer},
                        {disabled, boolean}], require_admin);
request(U, setslot, A) ->
    api(U, setslot, A, [{machine, atom},
                        {slot, integer},
                        {name},
                        {price, integer},
                        {available, integer},
                        {disabled, boolean}], require_admin);
request(U, delslot, A) ->
    api(U, delslot, A, [{machine, atom},
                        {slot, integer}], require_admin);
request(U, temperatures, A) ->
    api(U, temperatures, A, [{from, integer},
                             {length, integer}]);
request(U, userinfo, A) ->
    api(U, userinfo, A, [{user}]);
request(U, addmachine, A) ->
    api(U, addmachine, A, [{machine, atom},
                           {name},
                           {password},
                           {public_ip, ip},
                           {available_sensor, boolean},
                           {machine_ip, ip},
                           {allow_connect, boolean},
                           {admin_only, boolean}], require_admin);
request(U, modmachine, A) ->
    api(U, modmachine, A, [{machine, atom},
                           {name},
                           {password},
                           {public_ip, ip},
                           {available_sensor, boolean},
                           {machine_ip, ip},
                           {allow_connect, boolean},
                           {admin_only, boolean}]);
request(U, delmachine, A) ->
    api(U, delmachine, A, [{machine, atom}], require_admin);
request(U, getconnections, A) ->
    api(U, getconnections, A, []);
request(U, addapp, A) ->
    api(U, addapp, A, [{name, atom},
                       {description}]);
request(U, getapps, A) ->
    api(U, getapps, A, []);
request(U, delapp, A) ->
    api(U, delapp, A, [{name, atom}]);
request(_, _, _) ->
    error(unknown_command).

api(UserRef, Api, A, Args, require_admin) ->
    case user_auth:can_admin(UserRef) of
        true -> api(UserRef, Api, A, Args);
        false -> error(permission_denied)
    end.

api(UserRef, Api, A, Args) ->
    error_logger:error_msg("Got args: ~p~n", [[UserRef] ++ args(A, Args)]),
    case args(A, Args) of
        {error, Reason} -> {error, Reason};
        Arguments -> apply(?MODULE, Api, [UserRef] ++ Arguments)
    end.

currentuser(U) ->
    userref_to_struct(U).

drop(U, Machine, Slot, 0) -> drop(U, Machine, Slot);
drop(U, Machine, Slot, Delay) ->
	receive
	after Delay * 1000 ->
		drop(U, Machine, Slot)
	end.
drop(U, Machine, Slot) ->
    case user_auth:drop(U, Machine, Slot) of
        ok ->
            ok(true);
        {error, permission_denied} ->
            error(permission_denied);
        {error, slot_empty} ->
            error(slot_empty);
        {error, machine_down} ->
            error(machine_down);
        {error, Reason} ->
            error(Reason);
        _Else ->
            error(unknown)
    end.

logs(U, Offset, Limit) when Offset >= 0, Limit =< 100 ->
    case drink_log:get_logs(U, Offset, Limit) of
        {ok, Data} ->
            ok(format_logs(Offset, Limit, Data));
        {error, Reason} ->
            error(Reason)
    end;
logs(_, _, _) ->
    error(invalid_args).

machines(U) ->
    ok({struct, dump_machines(user_auth:can_admin(U), drink_machines_sup:machines())}).

moduser(U, UserName, Attr, Value, ModReason) ->
    case user_auth:admin(U, UserName) of
        {ok, User} ->
            mod_user(User, Attr, Value, ModReason);
        {error, permission_denied} ->
            error(permission_denied);
        {error, invalid_user} ->
            error(invalid_user);
        {error, Reason} ->
            error(Reason);
        _Else ->
            error(unknown)
    end.

addslot(U, Machine, Slot, Name, Price, Avail, Disabled) ->
    case drink_machine:add_slot(#slot{
        machine = Machine,
        num = Slot,
        name = Name,
        price = Price,
        avail = Avail,
        disabled = Disabled
    }) of
        ok ->
            ok(true);
        {error, permission_denied} ->
            error(permission_denied);
        {error, Reason} ->
            error(Reason)
    end.

setslot(U, Machine, Slot, Name, Price, Avail, Disabled) ->
    case drink_machine:set_slot_info(U, #slot{
        machine = Machine,
        num = Slot,
        name = Name,
        price = Price,
        avail = Avail,
        disabled = Disabled
    }) of
        ok ->
            ok(true);
        {error, permission_denied} ->
            error(permission_denied);
        {error, Reason} ->
            error(Reason)
    end.

delslot(U, Machine, Slot) ->
    case drink_machine:del_slot(Machine, Slot) of
        ok ->
            ok(true);
        {error, Reason} ->
            error(Reason)
    end.

temperatures(_, From, Limit) when From >= 0, Limit >= 0, Limit =< 100000 ->
    FromSecs = From + calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}}),
    FromDate = calendar:gregorian_seconds_to_datetime(FromSecs),
    case drink_log:get_temps(FromDate, Limit) of
        {ok, Data} ->
            ok(format_temps(From, Limit, Data));
        {error, Reason} ->
            error(Reason)
    end;
temperatures(_, _, _) ->
    error(invalid_args).

userinfo(U, UserName) ->
    case user_auth:user(U, UserName) of
       {ok, User} ->
           Ret = userref_to_struct(User),
           user_auth:delete_ref(User),
           Ret;
       _Else ->
           error(invalid_user)
    end.

addmachine(_, MachineAtom, MachineName, MachinePassword, MachinePublicIP, MachineAvailableSensor, MachineIP, MachineAllowConnect, MachineAdminOnly) ->
    case drink_machines_sup:add(#machine{machine = MachineAtom,
                                         password = MachinePassword,
                                         name = MachineName,
                                         public_ip = MachinePublicIP,
                                         available_sensor = MachineAvailableSensor,
                                         machine_ip = MachineIP,
                                         allow_connect = MachineAllowConnect,
                                         admin_only = MachineAdminOnly}) of
        ok -> ok(true);
        _  -> error(unknown_error)
    end.

modmachine(_, MachineAtom, MachineName, MachinePassword, MachinePublicIP, MachineAvailableSensor, MachineIP, MachineAllowConnect, MachineAdminOnly) ->
    case drink_machines_sup:mod(#machine{machine = MachineAtom,
                                         password = MachinePassword,
                                         name = MachineName,
                                         public_ip = MachinePublicIP,
                                         available_sensor = MachineAvailableSensor,
                                         machine_ip = MachineIP,
                                         allow_connect = MachineAllowConnect,
                                         admin_only = MachineAdminOnly}) of
        ok -> ok(true);
        _ -> error(unknown_error)
    end.

delmachine(_, Machine) ->
    case drink_machines_sup:del(Machine) of
        ok -> ok(true);
        _ -> error(unknown_error)
    end.

getconnections(_) ->
    case drink_connections:get() of
        {ok, List} ->
            ok(format_connections(List));
        _ -> error(unknown_error)
    end.

addapp(U, Name, Description) ->
    case user_auth:user_info(U) of
        {ok, UserInfo} ->
            case drink_app_auth_api:app_register(Name, UserInfo#user.username, Description, []) of
                ok -> ok(true);
                _ -> error(unknown_error)
            end;
        _ -> error(permission_denied)
    end.

getapps(_) ->
    case drink_app_auth_api:app_list() of
        {ok, List} ->
            ok(format_apps([ drink_app_auth_api:app_get(App) || App <- List ]));
        _ -> error(unknown_error)
    end.

delapp(U, Name) ->
    case {user_auth:can_admin(U), user_auth:user_info(U), drink_app_auth_api:app_get(Name)} of
        {true, _, _} ->
            case drink_app_auth_api:app_delete(Name) of
                ok -> ok(true);
                _ -> error(unknown_error)
            end;
        {_, {ok, #user{ username = UserName }}, {ok, #app{ owner = UserName }}} ->
            case drink_app_auth_api:app_delete(Name) of
                ok -> ok(true);
                _ -> error(unknown_error)
            end;
        _ ->
            error(permission_denied)
    end.

ok(Data) ->
    {ok, Data}.

error(Reason) ->
    {error, Reason}.

dump_machines(_Admin, []) ->
    [];
dump_machines(false, [M|Machines]) ->
    case drink_machine:admin_only(M) of
        {ok, true} -> dump_machines(false, Machines);
        _ -> [{M, machine_stat(false, M)}] ++ dump_machines(false, Machines)
    end;
dump_machines(true, [M|Machines]) ->
    [{M, machine_stat(true, M)}] ++ dump_machines(true, Machines).

machine_stat(false, Machine) ->
    case drink_machine:slots(Machine) of
        {ok, Slots} ->
            {struct, [
                {machineid, atom_to_list(Machine)},
                {name, machine_attr(Machine, name, atom_to_list(Machine))},
                {connected, drink_machine:is_alive(Machine)},
                {temperature, machine_attr(Machine, temperature, 0)},
                {slots, {struct, slots(Slots)}}
            ]};
        _Else ->
            false
    end;
machine_stat(true, Machine) ->
    case drink_machine:slots(Machine) of
        {ok, Slots} ->
            {struct, [
                {machineid, atom_to_list(Machine)},
                {name, machine_attr(Machine, name, atom_to_list(Machine))},
                {connected, drink_machine:is_alive(Machine)},
                {temperature, machine_attr(Machine, temperature, 0)},
                {password, machine_attr(Machine, password, "")},
                {public_ip, ip_to_list(machine_attr(Machine, public_ip, ""))},
                {available_sensor, machine_attr(Machine, available_sensor, false)},
                {machine_ip, ip_to_list(machine_attr(Machine, machine_ip, ""))},
                {allow_connect, machine_attr(Machine, allow_connect, false)},
                {admin_only, machine_attr(Machine, admin_only, false)},
                {slots, {struct, slots(Slots)}}
            ]};
        _Else ->
            false
    end.

machine_attr(Machine, Attr, Default) ->
    case drink_machine:Attr(Machine) of
        {ok, Name} ->
            Name;
        _Else ->
            Default
    end.

slots([]) ->
    [];
slots([S|Slots]) ->
    [{integer_to_list(S#slot.num), slot_stat(S)}] ++ slots(Slots).

slot_stat(Slot) ->
    {struct, [
        {num, Slot#slot.num},
        {name, Slot#slot.name},
        {price, Slot#slot.price},
        {available, Slot#slot.avail},
        {disabled, Slot#slot.disabled}
    ]}.

ip_to_list(false) ->
    false;
ip_to_list({A,B,C,D}) ->
    lists:flatten(io_lib:format("~w.~w.~w.~w", [A,B,C,D])).

userref_to_struct(UserRef) ->
    case user_auth:user_info(UserRef) of
        {ok, UserInfo} ->
            ok({struct, [
                {username, UserInfo#user.username},
                {credits, UserInfo#user.credits},
                {admin, UserInfo#user.admin},
                {ibuttons, {array, UserInfo#user.ibuttons}}
            ]});
        {error, _Reason} ->
            error(invalid_user)
    end.

mod_user(UserRef, admin, "true", ModReason) -> mod_user(UserRef, admin, true, ModReason);
mod_user(UserRef, admin, "false", ModReason) -> mod_user(UserRef, admin, false, ModReason);
mod_user(UserRef, admin, Value, _) when is_atom(Value) ->
    case user_auth:set_admin(UserRef, Value) of
        ok ->
            userref_to_struct(UserRef);
        {error, Reason} ->
            error(Reason)
    end;
mod_user(UserRef, modcredits, Value, ModReason) when is_list(Value) ->
    case string:to_integer(Value) of
        {error, _Reason} ->
            error(invalid_args);
        {IntValue, _Rest} ->
            mod_user(UserRef, modcredits, IntValue, ModReason)
    end;
mod_user(UserRef, modcredits, Value, ModReason) when is_integer(Value) ->
    case user_auth:mod_credits(UserRef, Value, list_to_atom(ModReason)) of
        ok ->
            userref_to_struct(UserRef);
        {error, Reason} ->
            error(Reason)
    end;
mod_user(UserRef, delibutton, Value, _ModReason) ->
    case user_auth:del_ibutton(UserRef, Value) of
        ok ->
            userref_to_struct(UserRef);
        {error, Reason} ->
            error(Reason)
    end;
mod_user(UserRef, addibutton, Value, _ModReason) ->
    case user_auth:add_ibutton(UserRef, Value) of
        ok ->
            userref_to_struct(UserRef);
        {error, Reason} ->
            error(Reason)
    end;
mod_user(_, _, _, _) ->
    error(invalid_args).

format_logs(Start, Length, Data) ->
    {struct, [{start, Start}, {length, Length}, {lines, {array, lists:map(fun format_log/1, Data)}}]}.

format_log(Line = #money_log{}) ->
    {struct, [
        {type, "money"},
        {time, format_time(Line#money_log.time)},
        {username, Line#money_log.username},
        {admin, Line#money_log.admin},
        {amount, Line#money_log.amount},
        {direction, atom_to_list(Line#money_log.direction)},
        {reason, atom_to_list(Line#money_log.reason)}
    ]};
format_log(Line = #drop_log{}) ->
    {struct, [
        {type, "drop"}, 
        {machine, atom_to_list(Line#drop_log.machine)},
        {slot, Line#drop_log.slot},
        {username, Line#drop_log.username},
        {time, format_time(Line#drop_log.time)},
        {status, Line#drop_log.status}
    ]}.

format_temps(Start, Length, Data) ->
    {struct, [{start, Start}, {length, Length}, {machines, {struct, 
        [ temperature_data(M, Data) || M <- temperature_machines(Data) ]}}]}.

temperature_machines(Data) ->
    lists:usort([ X#temperature.machine || X <- Data ]).

temperature_data(Machine, Data) ->
    {Machine, {array, lists:map(fun format_temp/1,
        lists:filter(fun(E) -> E#temperature.machine =:= Machine end, Data))}}.

format_temp(Temp = #temperature{}) ->
    {array, [format_time(Temp#temperature.time), Temp#temperature.temperature]}.

format_connections(List) ->
    {array, [ format_connection(X) || X <- List ]}.

format_connection({Pid, Username, Transport, App}) ->
    {struct, [{pid, pid_to_list(Pid)},
              {username, Username},
              {transport, atom_to_list(Transport)},
              {app, atom_to_list(App)}]}.

format_apps(List) ->
    {array, [ format_app(X) || X <- List ]}.

format_app({ok, AppInfo = #app{}}) ->
    {struct, [{name, atom_to_list(AppInfo#app.name)},
              {owner, AppInfo#app.owner},
              {description, AppInfo#app.description}]}.

format_time(Time) ->
    calendar:datetime_to_gregorian_seconds(Time) -
    calendar:datetime_to_gregorian_seconds({{1970,1,1}, {0,0,0}}).

encode_event(UserRef, Provider, Event) ->
    case encode_event_data(UserRef, Provider, Event) of
        false ->
            json:encode({struct, [{event, atom_to_list(element(1, Event))}]});
        Data ->
            json:encode({struct, [{event, atom_to_list(element(1, Event))},
                                  {data, Data}]})
    end.

encode_event_data(UserRef, drink, MoneyLog = #money_log{}) ->
    {struct, [{time, format_time(MoneyLog#money_log.time)},
              {username, MoneyLog#money_log.username},
              {admin, stringify(MoneyLog#money_log.admin)},
              {amount, MoneyLog#money_log.amount},
              {direction, atom_to_list(MoneyLog#money_log.direction)},
              {reason, atom_to_list(MoneyLog#money_log.reason)}]};
encode_event_data(UserRef, drink, {user_changed, Username, Changes}) ->
    {struct, [{username, Username}] ++ encode_user_changes(Changes)};
encode_event_data(UserRef, drink, {machine_added, Machine}) ->
    % TODO: we already have the full machine object, no need to get the info again
    machine_stat(user_auth:can_admin(UserRef), Machine#machine.machine);
encode_event_data(UserRef, drink, {machine_modified, OldMachine, Machine}) ->
    % TODO: we already have the full machine object, no need to get the info again
    machine_stat(user_auth:can_admin(UserRef), Machine#machine.machine);
encode_event_data(UserRef, drink, {machine_deleted, Machine}) ->
    {struct, [{machineid, atom_to_list(Machine#machine.machine)}]};
encode_event_data(UserRef, drink, {machine_connected, Machine}) ->
    {struct, [{machineid, atom_to_list(Machine)}]};
encode_event_data(UserRef, drink, {machine_disconnected, Machine}) ->
    {struct, [{machineid, atom_to_list(Machine)}]};
encode_event_data(UserRef, drink, {slot_added, Machine, Slot}) ->
    {struct, [{machineid, atom_to_list(Machine#machine.machine)}, {slot, slot_stat(Slot)}]};
encode_event_data(UserRef, drink, {slot_modified, Machine, Slot}) ->
    {struct, [{machineid, atom_to_list(Machine#machine.machine)}, {slot, slot_stat(Slot)}]};
encode_event_data(UserRef, drink, {slot_deleted, Machine, Slot}) ->
    {struct, [{machineid, atom_to_list(Machine#machine.machine)}, {slot, Slot}]};
encode_event_data(UserRef, drink, T = #temperature{}) ->
    {struct, [{machine, atom_to_list(T#temperature.machine)},
              {time, format_time(T#temperature.time)},
              {temperature, T#temperature.temperature}]};
encode_event_data(UserRef, drink, D = #drop_log{}) ->
    {struct, [{machine, atom_to_list(D#drop_log.machine)},
              {slot, D#drop_log.slot},
              {time, format_time(D#drop_log.time)},
              {status, atom_to_list(D#drop_log.status)},
              {username, D#drop_log.username}]};
encode_event_data(_, drink, _) ->
    false;
encode_event_data(_UserRef, drink_connections, {connected, Pid, Username, Transport, App}) ->
    {struct, [{pid, pid_to_list(Pid)},
              {username, Username},
              {transport, atom_to_list(Transport)},
              {app, atom_to_list(App)}]};
encode_event_data(_UserRef, drink_connections, {disconnected, Pid}) ->
    {struct, [{pid, pid_to_list(Pid)}]};
encode_event_data(_, drink_connections, _) -> false;
encode_event_data(_, drink_app_auth, {app_new, App}) ->
    {struct, [{name, atom_to_list(App#app.name)},
              {owner, App#app.owner},
              {description, App#app.description}]};
encode_event_data(_, drink_app_auth, {app_deleted, Name}) ->
    {struct, [{name, atom_to_list(Name)}]};
encode_event_data(_, _, _) -> false.

encode_user_changes([]) -> [];
encode_user_changes([{add_ibutton, IButton}|T]) ->
    [{add_ibutton, IButton}] ++ encode_user_changes(T);
encode_user_changes([{del_ibutton, IButton}|T]) ->
    [{del_ibutton, IButton}] ++ encode_user_changes(T);
encode_user_changes([{admin, Old, New}|T]) ->
    [{admin, {struct, [{old, Old}, {new, New}]}}] ++ encode_user_changes(T);
encode_user_changes([_|T]) ->
    [] ++ encode_user_changes(T).

stringify(L) when is_list(L) -> L;
stringify(nil) -> "".
