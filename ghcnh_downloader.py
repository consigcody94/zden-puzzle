#!/usr/bin/env python3
"""
GHCN-Hourly Data Downloader and Processor
Downloads hourly weather data for specified FAA station codes,
filters by date range, and bundles into monthly ZIP files.

Usage:
    python ghcnh_downloader.py

Output:
    Creates monthly ZIP files in format: MMYYYY_STATIONID.zip
    (e.g., 082025_KJFK.zip for August 2025 JFK data)
"""

import os
import csv
import zipfile
import requests
from io import StringIO
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Configuration
OUTPUT_DIR = Path("ghcnh_output")
DATE_START = datetime(2025, 8, 1)
DATE_END = datetime(2025, 12, 31)
MAX_WORKERS = 5  # Concurrent downloads - be nice to NOAA servers
STATION_LIST_URL = "https://www.ncei.noaa.gov/oa/global-historical-climatology-network/hourly/doc/ghcnh-station-list.csv"
DATA_BASE_URL = "https://www.ncei.noaa.gov/oa/global-historical-climatology-network/hourly/access/by-station/"

# 909 FAA station codes provided by user
FAA_CODES = [
    "0j4", "12n", "bcr", "1v4", "2wx", "40b", "6r6", "79j", "8d3", "9v9",
    "aaf", "aao", "aat", "abe", "abi", "abq", "abr", "aby", "ack", "act",
    "acv", "acy", "adg", "adq", "aex", "afn", "afw", "agc", "ags", "ahn",
    "aia", "akh", "akn", "ako", "akq", "akr", "akw", "alb", "ali", "alk",
    "alo", "als", "alw", "ama", "amg", "amw", "anb", "anc", "and", "anj",
    "aoh", "aoo", "apa", "apc", "apf", "apn", "aqt", "aqv", "aqw", "ara",
    "arb", "arr", "art", "asd", "ase", "ast", "asx", "atl", "att", "aty",
    "aug", "aus", "auw", "avl", "avp", "avx", "awi", "awm", "axn", "azo",
    "baf", "baz", "bbw", "bce", "bde", "bdl", "bdr", "bed", "beh", "bet",
    "bfd", "bff", "bfi", "bfl", "bfm", "bgd", "bgm", "bgr", "bhk", "bhm",
    "bid", "big", "bih", "bil", "bis", "biv", "bjj", "bkb", "bke", "bkl",
    "bkv", "bkw", "blf", "blh", "bli", "blm", "blu", "bmg", "bml", "bmq",
    "bna", "bno", "boi", "bos", "bpi", "bpk", "bpt", "brd", "brl", "bro",
    "brw", "btl", "btm", "btr", "btt", "btv", "buf", "bur", "buy", "bvo",
    "bvy", "bwg", "bwi", "byg", "byi", "bzn", "cae", "cag", "cak", "cao",
    "car", "ccr", "cdb", "cdc", "cdj", "cdr", "cds", "cdv", "cdw", "cec",
    "ceu", "cew", "cez", "cfv", "cgf", "cgi", "cha", "cho", "chs", "cid",
    "ckb", "ckv", "cle", "cll", "clm", "clt", "cma", "cmh", "cmi", "cmx",
    "cnk", "cnm", "cno", "cnu", "cny", "con", "cos", "cot", "cou", "cpr",
    "cps", "cqc", "cqt", "cqx", "cre", "crg", "crp", "crq", "crs", "crw",
    "csg", "csm", "csv", "ctb", "cty", "cub", "cut", "cvg", "cxo", "cxy",
    "cys", "d07", "dab", "dag", "dal", "dan", "daw", "day", "dbq", "dca",
    "dcu", "ddc", "ddh", "dec", "ded", "deq", "det", "dew", "dfi", "dfw",
    "dgw", "dhn", "dht", "dik", "dkk", "dlh", "dln", "dls", "dmn", "dmo",
    "dnl", "dpa", "dra", "dro", "drt", "dsm", "dsv", "dtn", "dto", "dts",
    "dtw", "dug", "duj", "dvn", "dvt", "dwh", "dxr", "dyl", "eaa", "eat",
    "eau", "ecg", "ecp", "eed", "eeo", "eet", "efk", "ekn", "eko", "eld",
    "elm", "eln", "elp", "ely", "elz", "emp", "ena", "enn", "enw", "eph",
    "eqy", "eri", "esf", "est", "euf", "eug", "evv", "evw", "ewb", "ewn",
    "ewr", "eye", "eyw", "fai", "far", "fat", "fay", "fcm", "fdr", "fdy",
    "ffc", "fft", "ffz", "fhr", "fig", "fit", "fld", "flg", "fll", "flo",
    "fmn", "fmy", "fnb", "fnt", "foe", "fok", "fpr", "frg", "fsd", "fsm",
    "fst", "ftw", "fty", "ful", "fve", "fwa", "fwn", "fxe", "fyv", "fzy",
    "gag", "gcc", "gck", "gcn", "gdp", "ged", "geg", "gey", "gez", "gfk",
    "gfl", "ggg", "ggw", "gif", "gjt", "gkj", "gkn", "gky", "gld", "glh",
    "glr", "gls", "gmu", "gna", "gnr", "gnt", "gnv", "gok", "gon", "gpi",
    "gpt", "grb", "grd", "gri", "grr", "gsh", "gso", "gsp", "gtf", "gup",
    "guy", "gvl", "gwo", "gzh", "hao", "hbg", "hbr", "hdo", "hei", "hfd",
    "hgr", "hhr", "hib", "hie", "hio", "hjo", "hka", "hks", "hky", "hlc",
    "hlg", "hln", "hns", "hom", "hon", "hot", "hou", "hpn", "hqm", "hri",
    "hrl", "hro", "hse", "hsi", "hsv", "htl", "hts", "huf", "hul", "hut",
    "hvn", "hvr", "hwd", "hwo", "hwv", "hya", "hyr", "hzy", "iad", "iag",
    "iah", "icr", "ict", "ida", "ien", "igm", "ijd", "ilg", "ili", "ilm",
    "iln", "iml", "imt", "ind", "ink", "inl", "int", "inw", "iow", "ipl",
    "ipt", "irk", "ism", "isp", "isw", "ith", "itr", "iwi", "ixd", "izg",
    "jan", "jax", "jbr", "jct", "jdn", "jef", "jer", "jfk", "jhw", "jkl",
    "jln", "jms", "jnr", "jnu", "jrf", "jst", "jxn", "kal", "ktn", "kvl",
    "laa", "laf", "lan", "lar", "las", "law", "lax", "lbb", "lbf", "lbt",
    "lbx", "lch", "leb", "lee", "lex", "lfk", "lft", "lga", "lgb", "lgu",
    "lhd", "lhq", "lhx", "lic", "lit", "lkv", "llj", "llq", "lmt", "lnd",
    "lnk", "lnr", "lns", "lol", "lou", "loz", "lpr", "lrd", "lse", "luk",
    "lvj", "lvk", "lvm", "lvs", "lwc", "lwd", "lwm", "lws", "lwt", "lwv",
    "lxt", "lxv", "lyh", "mae", "maf", "mai", "mbg", "mbs", "mcb", "mce",
    "mcg", "mci", "mck", "mcn", "mco", "mcw", "mdh", "mdt", "mdw", "meb",
    "meh", "mei", "mem", "mfd", "mfe", "mfi", "mfr", "mgj", "mgm", "mgw",
    "mgy", "mhe", "mhk", "mhs", "mht", "mia", "mic", "mie", "miv", "miw",
    "mkc", "mke", "mkg", "mkl", "mko", "mlb", "mlc", "mlf", "mli", "mlp",
    "mls", "mlt", "mlu", "mmk", "mmu", "mmv", "mnn", "mob", "mod", "mot",
    "mpo", "mpv", "mrb", "mrh", "mri", "mry", "msl", "msn", "mso", "msp",
    "mss", "msy", "mth", "mtj", "mto", "mtp", "mvl", "mvy", "mwh", "mwl",
    "mwt", "myf", "myl", "myv", "n60", "nak", "new", "npa", "nui", "nuq",
    "nyc", "oak", "odo", "odx", "ofk", "ofp", "ogb", "ogd", "ojc", "okb",
    "okc", "olf", "olm", "ols", "oma", "ome", "omk", "ono", "ont", "opf",
    "oqt", "ord", "ore", "orf", "orh", "orl", "ort", "osh", "osu", "oth",
    "otm", "otz", "ove", "ovs", "owd", "oxb", "oxr", "p28", "p53", "p58",
    "p59", "p60", "p68", "p69", "p92", "pae", "pah", "pao", "paq", "pbf",
    "pbg", "pbi", "pbv", "pdk", "pdt", "pdx", "peo", "pga", "pgd", "phd",
    "phf", "phl", "php", "phx", "pia", "pie", "pih", "pil", "pir", "pit",
    "pkb", "pkd", "pln", "pmd", "pmp", "pnc", "pne", "pns", "pof", "por",
    "pou", "ppf", "pql", "prb", "prc", "prn", "psc", "psf", "psp", "psx",
    "ptk", "ptw", "pub", "puc", "puw", "pvc", "pvd", "pwa", "pwk", "pwm",
    "pym", "rac", "ral", "rap", "rbd", "rbg", "rbl", "rdd", "rdg", "rdm",
    "rdu", "reo", "rfd", "rhi", "ric", "ril", "riw", "rkp", "rks", "rme",
    "rmg", "rnm", "rno", "rnt", "roa", "roc", "row", "rqe", "rsl", "rst",
    "rsw", "rtn", "rue", "rut", "rvs", "rwf", "rwi", "rwl", "rxe", "sac",
    "sad", "saf", "san", "sat", "sav", "saw", "sba", "sbm", "sbn", "sbp",
    "sby", "scc", "sch", "sck", "sdb", "sdf", "sdl", "sdm", "sea", "seg",
    "set", "sfb", "sff", "sfo", "sfz", "sgf", "sgr", "sgy", "shn", "shr",
    "shv", "sit", "siy", "sjc", "sjn", "sjt", "sju", "slc", "sle", "slk",
    "sln", "smf", "smo", "smp", "smq", "smx", "sna", "snp", "sns", "snt",
    "sny", "sov", "spb", "spd", "spg", "spi", "sps", "spw", "srq", "ssf",
    "ssi", "stc", "stj", "stl", "stp", "sts", "stt", "stx", "sus", "sux",
    "swd", "swf", "swo", "sxt", "syr", "tad", "tal", "tan", "tcc", "tcl",
    "tcs", "tdz", "teb", "thv", "tiw", "tka", "tki", "tlh", "tmb", "toi",
    "tol", "top", "tor", "tpa", "tph", "tqe", "tri", "trl", "trm", "ttd",
    "ttn", "tul", "tup", "tus", "tvc", "tvl", "tvr", "twf", "txk", "tyr",
    "tys", "uao", "ugn", "uil", "uin", "uki", "uno", "uts", "uuu", "uza",
    "vay", "vcb", "vct", "vel", "vgt", "vih", "vld", "vny", "vpc", "vpz",
    "vrb", "vsf", "vta", "vtn", "vuo", "vys", "wal", "wjf", "wld", "wmc",
    "wrl", "wst", "wvi", "xna", "yak", "yip", "ykm", "yng", "zzv",
    # Hawaii, Guam, other Pacific
    "lih", "mkk", "hnl", "lny", "ogg", "gsn", "ito", "koa", "gum", "dee"
]

# Special region prefixes for ICAO conversion
HAWAII_CODES = {"lih", "mkk", "hnl", "lny", "ogg", "ito", "koa"}
GUAM_CODES = {"gum", "gsn"}
ALASKA_CODES = {
    "adq", "akn", "anc", "bet", "brw", "cdv", "dut", "eaa", "eil", "ena",
    "fai", "gkn", "hom", "ili", "jnu", "ktn", "mcg", "mri", "ome", "otz",
    "scc", "sit", "snp", "yak", "ann", "bett", "big", "cdb", "dln", "enn",
    "gam", "hns", "lhd", "nuq", "ore", "ort", "sov", "tka", "wal"
}


def faa_to_icao(faa_code: str) -> str:
    """Convert FAA 3-letter code to 4-letter ICAO code."""
    faa = faa_code.lower().strip()

    if faa in HAWAII_CODES:
        return f"PH{faa.upper()}"
    elif faa in GUAM_CODES:
        return f"PG{faa.upper()}"
    elif faa in ALASKA_CODES:
        return f"PA{faa.upper()}"
    else:
        # Continental US - add K prefix
        return f"K{faa.upper()}"


def download_station_list() -> dict:
    """Download and parse the GHCN station list, returning ICAO -> GHCN_ID mapping."""
    print("Downloading station list...")

    try:
        response = requests.get(STATION_LIST_URL, timeout=60)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error downloading station list: {e}")
        return {}

    icao_to_ghcn = {}

    # Parse CSV
    reader = csv.DictReader(StringIO(response.text))
    for row in reader:
        icao = row.get('ICAO', '').strip()
        ghcn_id = row.get('GHCN_ID', '').strip()

        if icao and ghcn_id:
            icao_to_ghcn[icao.upper()] = ghcn_id

    print(f"Loaded {len(icao_to_ghcn)} stations with ICAO codes")
    return icao_to_ghcn


def download_psv_file(ghcn_id: str, icao: str, output_dir: Path) -> Path | None:
    """Download a station's PSV file."""
    filename = f"GHCNh_{ghcn_id}_por.psv"
    url = f"{DATA_BASE_URL}{filename}"
    local_path = output_dir / "raw" / filename

    # Skip if already downloaded
    if local_path.exists():
        print(f"  [SKIP] {icao} - already downloaded")
        return local_path

    try:
        print(f"  [GET] {icao} ({ghcn_id})...")
        response = requests.get(url, timeout=300, stream=True)
        response.raise_for_status()

        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        size_mb = local_path.stat().st_size / (1024 * 1024)
        print(f"  [OK] {icao} - {size_mb:.1f} MB")
        return local_path

    except requests.RequestException as e:
        print(f"  [FAIL] {icao}: {e}")
        return None


def filter_and_bundle_data(psv_path: Path, icao: str, output_dir: Path):
    """Read PSV file, filter by date range, and create monthly ZIP files."""

    monthly_data = {}  # {(month, year): [rows]}

    try:
        with open(psv_path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f, delimiter='|')
            headers = reader.fieldnames

            for row in reader:
                try:
                    year = int(row.get('Year', 0))
                    month = int(row.get('Month', 0))
                    day = int(row.get('Day', 0))

                    row_date = datetime(year, month, day)

                    if DATE_START <= row_date <= DATE_END:
                        key = (month, year)
                        if key not in monthly_data:
                            monthly_data[key] = []
                        monthly_data[key].append(row)

                except (ValueError, TypeError):
                    continue

        # Create ZIP files for each month
        zip_dir = output_dir / "monthly_zips"
        zip_dir.mkdir(parents=True, exist_ok=True)

        for (month, year), rows in monthly_data.items():
            zip_filename = f"{month:02d}{year}_{icao}.zip"
            zip_path = zip_dir / zip_filename
            csv_filename = f"{month:02d}{year}_{icao}.csv"

            # Write CSV inside ZIP
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                csv_content = StringIO()
                writer = csv.DictWriter(csv_content, fieldnames=headers, delimiter=',')
                writer.writeheader()
                writer.writerows(rows)
                zf.writestr(csv_filename, csv_content.getvalue())

            print(f"    Created: {zip_filename} ({len(rows)} records)")

        return len(monthly_data)

    except Exception as e:
        print(f"    Error processing {icao}: {e}")
        return 0


def main():
    print("=" * 60)
    print("GHCN-Hourly Data Downloader")
    print(f"Date Range: {DATE_START.strftime('%Y-%m-%d')} to {DATE_END.strftime('%Y-%m-%d')}")
    print(f"Stations: {len(FAA_CODES)}")
    print("=" * 60)

    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Step 1: Download station list and create mapping
    icao_to_ghcn = download_station_list()

    if not icao_to_ghcn:
        print("ERROR: Could not download station list. Exiting.")
        return

    # Step 2: Map FAA codes to GHCN IDs
    print("\nMapping FAA codes to GHCN IDs...")
    station_mapping = {}
    not_found = []

    for faa in FAA_CODES:
        icao = faa_to_icao(faa)
        ghcn_id = icao_to_ghcn.get(icao)

        if ghcn_id:
            station_mapping[icao] = ghcn_id
        else:
            not_found.append((faa, icao))

    print(f"Mapped: {len(station_mapping)} stations")
    print(f"Not found: {len(not_found)} stations")

    # Save not found for reference
    if not_found:
        with open(OUTPUT_DIR / "stations_not_found.txt", 'w') as f:
            f.write("FAA_Code,ICAO_Code\n")
            for faa, icao in not_found:
                f.write(f"{faa},{icao}\n")
        print(f"  See: {OUTPUT_DIR / 'stations_not_found.txt'}")

    # Save mapping for reference
    with open(OUTPUT_DIR / "station_mapping.csv", 'w') as f:
        f.write("FAA,ICAO,GHCN_ID\n")
        for faa in FAA_CODES:
            icao = faa_to_icao(faa)
            ghcn_id = station_mapping.get(icao, "NOT_FOUND")
            f.write(f"{faa},{icao},{ghcn_id}\n")

    # Step 3: Download PSV files
    print(f"\nDownloading {len(station_mapping)} station files...")
    downloaded = []

    for icao, ghcn_id in station_mapping.items():
        result = download_psv_file(ghcn_id, icao, OUTPUT_DIR)
        if result:
            downloaded.append((icao, ghcn_id, result))
        time.sleep(0.5)  # Be nice to NOAA servers

    print(f"\nDownloaded: {len(downloaded)} files")

    # Step 4: Filter and create monthly ZIPs
    print(f"\nProcessing and creating monthly ZIP files...")

    for icao, ghcn_id, psv_path in downloaded:
        print(f"  Processing {icao}...")
        filter_and_bundle_data(psv_path, icao, OUTPUT_DIR)

    print("\n" + "=" * 60)
    print("COMPLETE!")
    print(f"Output directory: {OUTPUT_DIR.absolute()}")
    print(f"Monthly ZIPs in: {OUTPUT_DIR / 'monthly_zips'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
