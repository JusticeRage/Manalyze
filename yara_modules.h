/*
    This file is part of Spike Guard.

    Spike Guard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Spike Guard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Spike Guard.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _YARA_MODULES_H_
#define _YARA_MODULES_H_

#include <iostream>
#include <string>
#include <yara/yara.h>

#include "pe.h"

namespace modules {

int yara_callback(int message, YR_RULE* rule, void* data)
{
    switch(message)
    {
        case CALLBACK_MSG_RULE_MATCHING:
            std::cout << "PEiD Signature: " << rule->identifier << std::endl;
            return CALLBACK_CONTINUE;

        case CALLBACK_MSG_RULE_NOT_MATCHING:
            return CALLBACK_CONTINUE;
    }
    return CALLBACK_ERROR;
}

int peid_signature(sg::PE& pe)
{
	int result;
	YR_COMPILER* compiler = NULL;
	YR_RULES* rules = NULL	;
    FILE* rule_file = NULL;
    std::string rule_filename("./resources/peid.yara");
	yr_initialize();

    result = yr_rules_load(rule_filename.c_str(), &rules);
	if (result != ERROR_SUCCESS && result != ERROR_INVALID_FILE)
	{
		std::cout << "Could not load yara rules. (Yara Error 0x" << std::hex << result << ")" << std::endl;
		result = -1;
		goto END;
	}

    if (result == ERROR_INVALID_FILE)
    {
        if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
        {
            result = -1;
            goto END;
        }
        rule_file = fopen(rule_filename.c_str(), "r");
        if (rule_file == NULL)
        {
            result = -1;
            goto END;
        }
        result = yr_compiler_add_file(compiler, rule_file, NULL);
        if (result != ERROR_SUCCESS)
        {
            result = -1;
            goto END;
        }
        result = yr_compiler_get_rules(compiler, &rules);
        if (result != ERROR_SUCCESS)
        {
            result = -1;
            goto END;
        }

        // Yara setup done. Scan the file.
        result = yr_rules_scan_file(rules,
                                    pe.get_path().c_str(),  // Path to the file to scan
                                    yara_callback,          // Callback
                                    NULL,                   // User specified data
                                    FALSE,                  // We don't want a fast scan.
                                    0);                     // No timeout

    }

	END:
	if (compiler != NULL) {
		yr_compiler_destroy(compiler);
	}
    if (rule_file != NULL) {
        fclose(rule_file);
    }
	if (rules != NULL) {
		yr_rules_destroy(rules);
	}
	yr_finalize();
	return 0;
}

} // !namespace modules

#endif // !_YARA_MODULES_H_
