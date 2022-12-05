import json
import re
import shutil
import os

output_folder = "/c/skola/prototypes/{}".format
output_file = "/c/skola/prototypes/{}/{}".format

nonsig_parsers = ['android_app_usage', 'bencode', 'bodyfile', 'bsm_log', 'chrome_cache', 'chrome_preferences',
                  'cups_ipp', 'czip', 'filestat', 'firefox_cache', 'firefox_cache2', 'fish_history', 'java_idx',
                  'jsonl', 'mcafee_protection', 'networkminer_fileinfo', 'usnjrnl', 'opera_typed_history',
                  'opera_global', 'plist', 'pls_recall', 'recycle_bin', 'recycle_bin_info2', 'symantec_scanlog', 'text',
                  'trendmicro_vd', 'trendmicro_url', 'utmp', 'winjob', 'rplog']


def parsers_with_files(log_path, file_map_output="/mnt/c/skola/prototypes/parser_file_map.json"):
    with open(log_path) as f:
        parser_file_map = {"nonsig": {}, "signature": {}}
        string = f.read()
        extractors = re.search(r"<extractors> Active parsers: ((.*,).*)", string)
        parsers = extractors.group(1).split(",")
        file_size = 0

        for parser in parsers:
            signature = "nonsig" if parser in nonsig_parsers else "signature"

            parser = parser.strip()
            regex = re.compile("parsing file: (.*) with parser: {}\n.*<.*> (?!{})".format(parser, parser))
            files = re.findall(regex, string)

            if files:
                os.makedirs(output_folder(parser), exist_ok=True)
                parser_file_map[signature][parser] = {"files": [], "amount_files": len(files)}

                for file in files:
                    plugin_regex = re.compile(r"(<{}>|<{}_parser>) Parsing file: {} with plugin: (.*)\n".format(parser, parser, file))
                    plugins = re.findall(plugin_regex, string)
                    if plugins:
                        plugins = [x[1] for x in plugins]
                    parser_file_map[signature][parser]["files"].append({"name": file, "plugins": plugins})

                    file = file.split(":")[-1]
                    filename = file.split("/")[-1]
                    shutil.copyfile(file, output_file(parser, filename))

                print(f"{parser}: {len(files)}")
                file_size += len(files)

        with open(file_map_output, 'w') as f:
            json.dump(parser_file_map, f)

        print(f"Processed {file_size} files")

def file_with_parsers(log_path, file_map_output="/mnt/c/skola/prototypes/file_parser_map.json"):
    file_parser_map = {}

    with open(log_path) as f:
        string = f.read()
        extractors = re.search(r"<extractors> Active parsers: ((.*,).*)", string)
        parsers = extractors.group(1).split(",")

        for parser in parsers:
            parser = parser.strip()
            regex = re.compile("parsing file: (.*) with parser: {}\n.*<.*> (?!{})".format(parser, parser))
            files = re.findall(regex, string)

            for file in files:
                if file not in file_parser_map:
                    file_parser_map[file] = {"nonsig": parser in nonsig_parsers, "parsers": [], "parser_amount": 0}

                file_parser_map[file]["parsers"].append(parser)
                file_parser_map[file]["parser_amount"] += 1

    with open(file_map_output, 'w') as f:
        json.dump(file_parser_map, f)

if __name__ == "__main__":
    # parsers_with_files("/mnt/c/skola/plaso_output/all.log")
    file_with_parsers("/mnt/c/skola/plaso_output/all.log")