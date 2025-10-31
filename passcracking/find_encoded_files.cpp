// find_encoded_files.cpp
// g++ -std=c++17 -O2 find_encoded_files.cpp -o find_encoded_files
// Usage: ./find_encoded_files [-p start_path] [-o output.txt] [-h]

#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace fs = std::filesystem;

static std::string to_lower(std::string s){
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}

int main(int argc, char** argv){
    std::string start = "/";
    std::string out_file;
    // default patterns (trailing '*' is treated as prefix wildcard of the extension)
    std::vector<std::string> patterns = {
        ".xls", ".xls*", ".xltx", ".od*", ".doc", ".doc*", ".pdf",
        ".pot", ".pot*", ".pp*"
    };

    for(int i=1;i<argc;i++){
        if(std::strcmp(argv[i],"-p")==0 && i+1<argc){ start = argv[++i]; }
        else if(std::strcmp(argv[i],"-o")==0 && i+1<argc){ out_file = argv[++i]; }
        else if(std::strcmp(argv[i],"-h")==0){ 
            std::cout<<"Usage: "<<argv[0]<<" [-p start_path] [-o output.txt] [-h]\n";
            return 0;
        } else {
            std::cerr<<"Unknown arg: "<<argv[i]<<"\n";
            return 2;
        }
    }

    std::ofstream ofs;
    if(!out_file.empty()){
        ofs.open(out_file, std::ios::out | std::ios::trunc);
        if(!ofs){
            std::cerr<<"Cannot open output file: "<<out_file<<"\n";
            return 3;
        }
    }

    auto write_line = [&](const std::string &line){
        std::cout<<line<<"\n";
        if(ofs) ofs<<line<<"\n";
    };

    // exclusions: skip these mountpoints / directories (common noisy/virtual dirs)
    std::vector<std::string> exclude_prefixes = {
        "/proc", "/sys", "/dev", "/run", "/var/lib", "/usr/lib", "/usr/share", "/usr/fonts"
    };

    // normalize patterns for matching: we will treat patterns ending with '*' as "extension starts with this prefix"
    struct Pattern { std::string pat; bool wildcard; };
    std::vector<Pattern> pats;
    for(auto &p : patterns){
        if(!p.empty() && p.back()=='*'){
            pats.push_back({ to_lower(p.substr(0, p.size()-1)), true });
        } else {
            pats.push_back({ to_lower(p), false });
        }
    }

    write_line(std::string("Scan start: ") + start);

    // recursive traversal
    try {
        fs::recursive_directory_iterator it(start, fs::directory_options::skip_permission_denied);
        for(const auto &entry : it){
            // skip if entry path starts with an excluded prefix
            std::string path = entry.path().string();
            bool skip=false;
            for(const auto &ex: exclude_prefixes){
                if(path.rfind(ex, 0) == 0){ // starts with
                    skip = true;
                    break;
                }
            }
            if(skip) {
                if(entry.is_directory()) it.disable_recursion_pending(); // don't descend
                continue;
            }

            // only files
            std::error_code ec;
            if(!fs::is_regular_file(entry.path(), ec)) continue;

            std::string filename = entry.path().filename().string();
            std::string filename_low = to_lower(filename);

            // find extension-like suffix from last dot; if no dot, skip (no extension)
            auto pos = filename_low.find_last_of('.');
            if(pos == std::string::npos) continue;
            std::string ext = filename_low.substr(pos); // includes the dot, e.g. ".xlsx"

            // test each pattern
            bool match=false;
            for(const auto &pp : pats){
                if(pp.wildcard){
                    // wildcard means extension starts with pp.pat (e.g. ".xls")
                    if(ext.rfind(pp.pat, 0) == 0){ match = true; break; }
                } else {
                    if(ext == pp.pat){ match = true; break; }
                }
            }
            if(match){
                write_line(path);
            }
        }
    } catch(const std::exception &e){
        std::cerr<<"Traversal error: "<<e.what()<<"\n";
        return 4;
    }

    if(ofs) ofs.flush();
    write_line("Done.");
    return 0;
}
