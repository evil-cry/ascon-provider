#include "/home/akif/ascon-provider/v_params.h"
int vigenere_params_parse(const char *key)
{
    const char *p = key;
    switch (*p++) {
    case 'a':
    case 'A':
        switch (*p++) {
        case 'u':
        case 'U':
            switch (*p++) {
            case 't':
            case 'T':
                switch (*p++) {
                case 'h':
                case 'H':
                    switch (*p++) {
                    case 'o':
                    case 'O':
                        switch (*p++) {
                        case 'r':
                        case 'R':
                            switch (*p++) {
                            case '\0':
                                return V_PARAM_author;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'b':
    case 'B':
        switch (*p++) {
        case 'l':
        case 'L':
            switch (*p++) {
            case 'o':
            case 'O':
                switch (*p++) {
                case 'c':
                case 'C':
                    switch (*p++) {
                    case 'k':
                    case 'K':
                        switch (*p++) {
                        case 's':
                        case 'S':
                            switch (*p++) {
                            case 'i':
                            case 'I':
                                switch (*p++) {
                                case 'z':
                                case 'Z':
                                    switch (*p++) {
                                    case 'e':
                                    case 'E':
                                        switch (*p++) {
                                        case '\0':
                                            return V_PARAM_blocksize;
                                        }
                                        break;
                                    }
                                    break;
                                }
                                break;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        case 'u':
        case 'U':
            switch (*p++) {
            case 'i':
            case 'I':
                switch (*p++) {
                case 'l':
                case 'L':
                    switch (*p++) {
                    case 'd':
                    case 'D':
                        switch (*p++) {
                        case 'i':
                        case 'I':
                            switch (*p++) {
                            case 'n':
                            case 'N':
                                switch (*p++) {
                                case 'f':
                                case 'F':
                                    switch (*p++) {
                                    case 'o':
                                    case 'O':
                                        switch (*p++) {
                                        case '\0':
                                            return V_PARAM_buildinfo;
                                        }
                                        break;
                                    }
                                    break;
                                }
                                break;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'k':
    case 'K':
        switch (*p++) {
        case 'e':
        case 'E':
            switch (*p++) {
            case 'y':
            case 'Y':
                switch (*p++) {
                case 'l':
                case 'L':
                    switch (*p++) {
                    case 'e':
                    case 'E':
                        switch (*p++) {
                        case 'n':
                        case 'N':
                            switch (*p++) {
                            case '\0':
                                return V_PARAM_keylen;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'v':
    case 'V':
        switch (*p++) {
        case 'e':
        case 'E':
            switch (*p++) {
            case 'r':
            case 'R':
                switch (*p++) {
                case 's':
                case 'S':
                    switch (*p++) {
                    case 'i':
                    case 'I':
                        switch (*p++) {
                        case 'o':
                        case 'O':
                            switch (*p++) {
                            case 'n':
                            case 'N':
                                switch (*p++) {
                                case '\0':
                                    return V_PARAM_version;
                                }
                                break;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    }
    return 0;
}
