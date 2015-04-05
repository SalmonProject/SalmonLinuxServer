//Copyright 2015 The Salmon Censorship Circumvention Project
//
//This file is part of the Salmon Server (GNU/Linux).
//
//The Salmon Server (GNU/Linux) is free software; you can redistribute it and / or
//modify it under the terms of the GNU General Public License as published by
//the Free Software Foundation; either version 3 of the License, or
//(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//GNU General Public License for more details.
//
//The full text of the license can be found at:
//http://www.gnu.org/licenses/gpl.html

#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "stringLL.h"

void StringLL_free(StringLL* toFree)
{
	StringLL* cur = toFree;
	while (cur)
	{
		StringLL* theNext = cur->next;
		if (cur->str)
			free(cur->str);

		free(cur);
		cur = theNext;
	}
}

StringLL* newStringLL()
{
	StringLL* ret = (StringLL*)malloc(sizeof(StringLL));
	ret->str = 0;
	ret->next = 0;
	return ret;
}

StringLL* StringLL_add(StringLL* startNode, char* theString)
{
	StringLL* cur = startNode;

	while (cur->next)
		cur = cur->next;

	cur->next = newStringLL();

	if (!cur->str)
		cur->str = strdup(theString);
	else
		cur->next->str = strdup(theString);

	return cur->next;
}

BOOL StringLL_contains(StringLL* head, char* theString)
{
	BOOL ret = FALSE;
	StringLL* cur = head;
	while (cur)
	{
		if (cur->str && !strcmp(cur->str, theString))
			return TRUE;

		if (!cur->next)
			return FALSE;

		cur = cur->next;
	}
	return FALSE;
}