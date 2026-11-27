//! Offline embedded ASN database (`M2`) for zero-network cloud/VPS vs residential ISP classification.
//!
//! `KNOWN_ASNS` is strictly sorted in ascending order by `asn` so lookups run in `O(log N)`
//! via `binary_search_by_key` with zero heap allocations.

use cg_protocol::AsnClassification;

/// Static ASN classification record stored in [`KNOWN_ASNS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsnEntry {
    pub asn: u32,
    pub classification: AsnClassification,
    pub org: &'static str,
    /// True for well-known shared VPN / high-abuse proxy hosting pools (e.g. M247, Datacamp, Akari).
    pub high_abuse_proxy_pool: bool,
}

const fn entry(asn: u32, classification: AsnClassification, org: &'static str) -> AsnEntry {
    AsnEntry {
        asn,
        classification,
        org,
        high_abuse_proxy_pool: matches!(classification, AsnClassification::PublicProxyVpnTor),
    }
}

/// Strictly sorted (`asn` ascending) offline lookup table covering 250+ major cloud/VPS
/// datacenters, high-abuse proxy pools, global residential ISPs, mobile carriers, and
/// education/research networks.
pub const KNOWN_ASNS: &[AsnEntry] = &[
    entry(
        3,
        AsnClassification::EducationGov,
        "Massachusetts Institute of Technology",
    ),
    entry(11, AsnClassification::EducationGov, "Harvard University"),
    entry(17, AsnClassification::EducationGov, "Purdue University"),
    entry(
        25,
        AsnClassification::EducationGov,
        "University of California, Berkeley",
    ),
    entry(32, AsnClassification::EducationGov, "Stanford University"),
    entry(
        174,
        AsnClassification::DatacenterHosting,
        "Cogent Communications",
    ),
    entry(
        209,
        AsnClassification::IspResidential,
        "CenturyLink / Lumen Residential",
    ),
    entry(513, AsnClassification::EducationGov, "CERN"),
    entry(577, AsnClassification::IspResidential, "Bell Canada"),
    entry(
        680,
        AsnClassification::EducationGov,
        "DFN German Research Network",
    ),
    entry(
        701,
        AsnClassification::IspResidential,
        "Verizon Fios / UUNET",
    ),
    entry(714, AsnClassification::BusinessIsp, "Apple Inc."),
    entry(
        786,
        AsnClassification::EducationGov,
        "JANET UK Academic Network",
    ),
    entry(
        812,
        AsnClassification::IspResidential,
        "Rogers Communications",
    ),
    entry(
        852,
        AsnClassification::IspResidential,
        "TELUS Communications",
    ),
    entry(
        906,
        AsnClassification::DatacenterHosting,
        "DMIT Cloud Services",
    ),
    entry(969, AsnClassification::DatacenterHosting, "Misaka Network"),
    entry(1136, AsnClassification::IspResidential, "KPN Netherlands"),
    entry(1221, AsnClassification::IspResidential, "Telstra Australia"),
    entry(1299, AsnClassification::BusinessIsp, "Arelion (Twelve99)"),
    entry(
        1314,
        AsnClassification::IspResidential,
        "True Internet Thailand",
    ),
    entry(
        1659,
        AsnClassification::EducationGov,
        "TANet Taiwan Academic Network",
    ),
    entry(2119, AsnClassification::IspResidential, "Telenor Norway"),
    entry(
        2497,
        AsnClassification::BusinessIsp,
        "Internet Initiative Japan (IIJ)",
    ),
    entry(
        2514,
        AsnClassification::BusinessIsp,
        "NTT PC Communications",
    ),
    entry(2516, AsnClassification::IspResidential, "KDDI Corporation"),
    entry(2518, AsnClassification::IspResidential, "BIGLOBE Japan"),
    entry(
        2519,
        AsnClassification::BusinessIsp,
        "Arteria Networks (Vectant)",
    ),
    entry(
        2527,
        AsnClassification::IspResidential,
        "Sony Network Communications (NURO)",
    ),
    entry(
        2635,
        AsnClassification::DatacenterHosting,
        "Automattic Cloud",
    ),
    entry(
        2856,
        AsnClassification::IspResidential,
        "British Telecommunications (BT)",
    ),
    entry(
        2906,
        AsnClassification::DatacenterHosting,
        "Netflix Streaming Services",
    ),
    entry(
        2907,
        AsnClassification::EducationGov,
        "SINET Japan Academic Network",
    ),
    entry(2914, AsnClassification::BusinessIsp, "NTT America"),
    entry(3209, AsnClassification::IspResidential, "Vodafone Germany"),
    entry(
        3215,
        AsnClassification::IspResidential,
        "Orange S.A. France",
    ),
    entry(
        3243,
        AsnClassification::IspResidential,
        "MEO / Altice Portugal",
    ),
    entry(3257, AsnClassification::BusinessIsp, "GTT Communications"),
    entry(
        3265,
        AsnClassification::IspResidential,
        "XS4ALL / KPN Netherlands",
    ),
    entry(
        3269,
        AsnClassification::IspResidential,
        "Telecom Italia (TIM)",
    ),
    entry(3292, AsnClassification::IspResidential, "TDC Denmark"),
    entry(3301, AsnClassification::IspResidential, "Telia Sweden"),
    entry(
        3303,
        AsnClassification::IspResidential,
        "Swisscom Switzerland",
    ),
    entry(
        3320,
        AsnClassification::IspResidential,
        "Deutsche Telekom AG",
    ),
    entry(
        3352,
        AsnClassification::IspResidential,
        "Telefonica Spain (Movistar)",
    ),
    entry(
        3356,
        AsnClassification::BusinessIsp,
        "Lumen / Level 3 Communications",
    ),
    entry(
        3462,
        AsnClassification::IspResidential,
        "Chunghwa Telecom (HiNet)",
    ),
    entry(
        3741,
        AsnClassification::BusinessIsp,
        "Internet Solutions South Africa",
    ),
    entry(
        3758,
        AsnClassification::IspResidential,
        "SingNet / Singtel Broadband",
    ),
    entry(3786, AsnClassification::IspResidential, "LG Uplus Korea"),
    entry(
        4134,
        AsnClassification::IspResidential,
        "China Telecom (ChinaNet)",
    ),
    entry(4515, AsnClassification::BusinessIsp, "PCCW Global"),
    entry(
        4538,
        AsnClassification::EducationGov,
        "CERNET China Education Network",
    ),
    entry(4657, AsnClassification::IspResidential, "StarHub Singapore"),
    entry(
        4694,
        AsnClassification::DatacenterHosting,
        "IDC Frontier Japan",
    ),
    entry(
        4713,
        AsnClassification::IspResidential,
        "NTT Communications (OCN)",
    ),
    entry(
        4716,
        AsnClassification::IspResidential,
        "NIFTY Corporation Japan",
    ),
    entry(
        4725,
        AsnClassification::IspResidential,
        "SoftBank / ODN Japan",
    ),
    entry(
        4760,
        AsnClassification::IspResidential,
        "HKT / PCCW Hong Kong",
    ),
    entry(
        4766,
        AsnClassification::IspResidential,
        "Korea Telecom (KT)",
    ),
    entry(4771, AsnClassification::IspResidential, "Spark New Zealand"),
    entry(
        4780,
        AsnClassification::IspResidential,
        "Seednet / FarEasTone Taiwan",
    ),
    entry(4788, AsnClassification::IspResidential, "Telekom Malaysia"),
    entry(4804, AsnClassification::IspResidential, "Optus Australia"),
    entry(
        4808,
        AsnClassification::IspResidential,
        "China Unicom Beijing",
    ),
    entry(4809, AsnClassification::BusinessIsp, "China Telecom CN2"),
    entry(
        4812,
        AsnClassification::IspResidential,
        "China Telecom Shanghai",
    ),
    entry(
        4837,
        AsnClassification::IspResidential,
        "China Unicom (CHINA169)",
    ),
    entry(
        4847,
        AsnClassification::BusinessIsp,
        "China Networks Inter-Exchange",
    ),
    entry(5089, AsnClassification::IspResidential, "Virgin Media UK"),
    entry(
        5378,
        AsnClassification::IspResidential,
        "Vodafone UK Broadband",
    ),
    entry(5384, AsnClassification::IspResidential, "Etisalat UAE"),
    entry(
        5410,
        AsnClassification::IspResidential,
        "Bouygues Telecom France",
    ),
    entry(5432, AsnClassification::IspResidential, "Proximus Belgium"),
    entry(5466, AsnClassification::IspResidential, "Eircom Ireland"),
    entry(5607, AsnClassification::IspResidential, "Sky UK Broadband"),
    entry(5617, AsnClassification::IspResidential, "Orange Polska"),
    entry(
        5650,
        AsnClassification::IspResidential,
        "Frontier Communications US",
    ),
    entry(
        5713,
        AsnClassification::IspResidential,
        "Telkom South Africa",
    ),
    entry(5769, AsnClassification::IspResidential, "Videotron Canada"),
    entry(
        6079,
        AsnClassification::IspResidential,
        "RCN / Astound Broadband US",
    ),
    entry(
        6128,
        AsnClassification::IspResidential,
        "Cablevision / Optimum US",
    ),
    entry(
        6167,
        AsnClassification::MobileCellular,
        "Verizon Wireless US",
    ),
    entry(
        6327,
        AsnClassification::IspResidential,
        "Shaw Communications Canada",
    ),
    entry(6667, AsnClassification::IspResidential, "Elisa Finland"),
    entry(
        6724,
        AsnClassification::DatacenterHosting,
        "STRATO AG Hosting",
    ),
    entry(
        6730,
        AsnClassification::IspResidential,
        "Sunrise Switzerland",
    ),
    entry(
        6805,
        AsnClassification::IspResidential,
        "Telefonica Germany (O2)",
    ),
    entry(
        6830,
        AsnClassification::IspResidential,
        "Liberty Global / UPC Europe",
    ),
    entry(6848, AsnClassification::IspResidential, "Telenet Belgium"),
    entry(
        6871,
        AsnClassification::IspResidential,
        "Plusnet UK Broadband",
    ),
    entry(
        6939,
        AsnClassification::DatacenterHosting,
        "Hurricane Electric",
    ),
    entry(
        7011,
        AsnClassification::IspResidential,
        "Frontier Communications",
    ),
    entry(7015, AsnClassification::BusinessIsp, "Comcast Business"),
    entry(7018, AsnClassification::IspResidential, "AT&T Services US"),
    entry(
        7029,
        AsnClassification::IspResidential,
        "Windstream Communications",
    ),
    entry(7303, AsnClassification::IspResidential, "Telecom Argentina"),
    entry(7473, AsnClassification::IspResidential, "Singtel Singapore"),
    entry(
        7497,
        AsnClassification::EducationGov,
        "CSTNET Chinese Academy of Sciences",
    ),
    entry(
        7506,
        AsnClassification::DatacenterHosting,
        "GMO Internet / ConoHa",
    ),
    entry(
        7545,
        AsnClassification::IspResidential,
        "TPG Telecom Australia",
    ),
    entry(7713, AsnClassification::IspResidential, "Telkom Indonesia"),
    entry(
        7922,
        AsnClassification::IspResidential,
        "Comcast Cable (Xfinity)",
    ),
    entry(
        8068,
        AsnClassification::DatacenterHosting,
        "Microsoft Corporation",
    ),
    entry(
        8069,
        AsnClassification::DatacenterHosting,
        "Microsoft Corporation",
    ),
    entry(
        8070,
        AsnClassification::DatacenterHosting,
        "Microsoft Corporation",
    ),
    entry(
        8075,
        AsnClassification::DatacenterHosting,
        "Microsoft Azure",
    ),
    entry(
        8100,
        AsnClassification::DatacenterHosting,
        "QuadraNet Enterprises",
    ),
    entry(
        8151,
        AsnClassification::IspResidential,
        "Telmex / Uninet Mexico",
    ),
    entry(
        8447,
        AsnClassification::IspResidential,
        "A1 Telekom Austria",
    ),
    entry(
        8560,
        AsnClassification::DatacenterHosting,
        "IONOS SE Hosting",
    ),
    entry(
        8881,
        AsnClassification::IspResidential,
        "1&1 Versatel Germany",
    ),
    entry(
        8987,
        AsnClassification::DatacenterHosting,
        "Amazon Data Services Ireland",
    ),
    entry(
        9009,
        AsnClassification::PublicProxyVpnTor,
        "M247 Europe (Shared Proxy/VPN Pool)",
    ),
    entry(9121, AsnClassification::IspResidential, "Turk Telekom"),
    entry(9143, AsnClassification::IspResidential, "Ziggo Netherlands"),
    entry(
        9269,
        AsnClassification::IspResidential,
        "Hong Kong Broadband Network (HKBN)",
    ),
    entry(9299, AsnClassification::IspResidential, "PLDT Philippines"),
    entry(
        9304,
        AsnClassification::IspResidential,
        "HGC Global Communications HK",
    ),
    entry(
        9318,
        AsnClassification::IspResidential,
        "SK Broadband Korea",
    ),
    entry(
        9370,
        AsnClassification::DatacenterHosting,
        "Sakura Internet Japan",
    ),
    entry(
        9371,
        AsnClassification::DatacenterHosting,
        "Sakura Internet Japan",
    ),
    entry(
        9500,
        AsnClassification::IspResidential,
        "One NZ / Vodafone New Zealand",
    ),
    entry(9605, AsnClassification::MobileCellular, "NTT DOCOMO Japan"),
    entry(
        9808,
        AsnClassification::IspResidential,
        "China Mobile (CMNET)",
    ),
    entry(9829, AsnClassification::IspResidential, "BSNL India"),
    entry(
        9924,
        AsnClassification::IspResidential,
        "Taiwan Fixed Network (TWM)",
    ),
    entry(
        9929,
        AsnClassification::BusinessIsp,
        "China Unicom CUII / 9929",
    ),
    entry(10013, AsnClassification::IspResidential, "FreeBit Japan"),
    entry(10099, AsnClassification::BusinessIsp, "China Unicom Global"),
    entry(
        10103,
        AsnClassification::IspResidential,
        "HGC Broadband Hong Kong",
    ),
    entry(
        10297,
        AsnClassification::DatacenterHosting,
        "Enzu / HostHatch Hosting",
    ),
    entry(
        10532,
        AsnClassification::DatacenterHosting,
        "Rackspace Hosting",
    ),
    entry(
        10796,
        AsnClassification::IspResidential,
        "Charter Communications (Spectrum)",
    ),
    entry(
        11351,
        AsnClassification::IspResidential,
        "Charter Communications (Spectrum)",
    ),
    entry(
        11427,
        AsnClassification::IspResidential,
        "Charter Communications (Spectrum)",
    ),
    entry(
        11492,
        AsnClassification::IspResidential,
        "Cable One / Sparklight US",
    ),
    entry(
        11537,
        AsnClassification::EducationGov,
        "Internet2 US Research Network",
    ),
    entry(11878, AsnClassification::DatacenterHosting, "tzulo Hosting"),
    entry(
        12076,
        AsnClassification::DatacenterHosting,
        "Microsoft Azure Edge",
    ),
    entry(
        12271,
        AsnClassification::IspResidential,
        "Charter Communications (Spectrum NY)",
    ),
    entry(
        12322,
        AsnClassification::IspResidential,
        "Free SAS (Proxad) France",
    ),
    entry(12430, AsnClassification::IspResidential, "Vodafone Spain"),
    entry(12479, AsnClassification::IspResidential, "Orange Spain"),
    entry(12576, AsnClassification::MobileCellular, "EE Limited UK"),
    entry(12874, AsnClassification::IspResidential, "Fastweb Italy"),
    entry(
        12876,
        AsnClassification::DatacenterHosting,
        "Scaleway / Online SAS",
    ),
    entry(
        13285,
        AsnClassification::IspResidential,
        "TalkTalk Communications UK",
    ),
    entry(
        13335,
        AsnClassification::DatacenterHosting,
        "Cloudflare Inc.",
    ),
    entry(
        13414,
        AsnClassification::DatacenterHosting,
        "X / Twitter Infrastructure",
    ),
    entry(
        14061,
        AsnClassification::DatacenterHosting,
        "DigitalOcean LLC",
    ),
    entry(14593, AsnClassification::IspResidential, "SpaceX Starlink"),
    entry(14609, AsnClassification::DatacenterHosting, "Equinix Metal"),
    entry(
        14618,
        AsnClassification::DatacenterHosting,
        "Amazon AWS (us-east)",
    ),
    entry(
        14907,
        AsnClassification::EducationGov,
        "Wikimedia Foundation",
    ),
    entry(
        15003,
        AsnClassification::DatacenterHosting,
        "Nobis Technology Group",
    ),
    entry(
        15133,
        AsnClassification::DatacenterHosting,
        "Edgio / EdgeCast CDN",
    ),
    entry(
        15169,
        AsnClassification::DatacenterHosting,
        "Google LLC / GCP",
    ),
    entry(15557, AsnClassification::IspResidential, "SFR France"),
    entry(
        16247,
        AsnClassification::PublicProxyVpnTor,
        "M247 UK (Shared Proxy/VPN Pool)",
    ),
    entry(
        16265,
        AsnClassification::DatacenterHosting,
        "Leaseweb Global",
    ),
    entry(16276, AsnClassification::DatacenterHosting, "OVH SAS"),
    entry(16509, AsnClassification::DatacenterHosting, "Amazon AWS"),
    entry(16591, AsnClassification::IspResidential, "Google Fiber US"),
    entry(
        16625,
        AsnClassification::DatacenterHosting,
        "Akamai Technologies",
    ),
    entry(
        17444,
        AsnClassification::MobileCellular,
        "China Mobile Hong Kong",
    ),
    entry(
        17506,
        AsnClassification::IspResidential,
        "UCOM / Arteria Broadband Japan",
    ),
    entry(
        17511,
        AsnClassification::IspResidential,
        "K-Opticom (eo Hikari) Japan",
    ),
    entry(
        17547,
        AsnClassification::IspResidential,
        "M1 Limited Singapore",
    ),
    entry(
        17621,
        AsnClassification::IspResidential,
        "China Unicom Shanghai",
    ),
    entry(
        17622,
        AsnClassification::IspResidential,
        "China Unicom Guangzhou",
    ),
    entry(
        17623,
        AsnClassification::IspResidential,
        "China Unicom Shenzhen",
    ),
    entry(
        17676,
        AsnClassification::IspResidential,
        "SoftBank BB Japan",
    ),
    entry(
        17816,
        AsnClassification::IspResidential,
        "China Unicom Guangdong",
    ),
    entry(
        18106,
        AsnClassification::IspResidential,
        "ViewQwest Singapore",
    ),
    entry(
        18126,
        AsnClassification::IspResidential,
        "Chubu Telecommunications (Commufa)",
    ),
    entry(18182, AsnClassification::IspResidential, "So-net Taiwan"),
    entry(
        18403,
        AsnClassification::IspResidential,
        "FPT Telecom Vietnam",
    ),
    entry(
        18881,
        AsnClassification::IspResidential,
        "Vivo / GVT Brazil",
    ),
    entry(18978, AsnClassification::DatacenterHosting, "Enzu Inc."),
    entry(
        19108,
        AsnClassification::IspResidential,
        "Altice USA / Suddenlink",
    ),
    entry(
        19318,
        AsnClassification::DatacenterHosting,
        "InterServer Hosting",
    ),
    entry(
        19527,
        AsnClassification::DatacenterHosting,
        "Google Cloud Edge",
    ),
    entry(
        19624,
        AsnClassification::DatacenterHosting,
        "DataPacket / CDN77",
    ),
    entry(
        19871,
        AsnClassification::DatacenterHosting,
        "Network Solutions Hosting",
    ),
    entry(
        19969,
        AsnClassification::DatacenterHosting,
        "Joe's Datacenter",
    ),
    entry(
        19994,
        AsnClassification::DatacenterHosting,
        "Rackspace Cloud",
    ),
    entry(
        20001,
        AsnClassification::IspResidential,
        "Charter Communications (Spectrum SoCal)",
    ),
    entry(20057, AsnClassification::MobileCellular, "AT&T Mobility US"),
    entry(
        20115,
        AsnClassification::IspResidential,
        "Charter Communications (Spectrum)",
    ),
    entry(
        20446,
        AsnClassification::DatacenterHosting,
        "Highwinds / StackPath",
    ),
    entry(
        20473,
        AsnClassification::DatacenterHosting,
        "Vultr / Constant (Choopa)",
    ),
    entry(
        20495,
        AsnClassification::DatacenterHosting,
        "WEDOS Internet Hosting",
    ),
    entry(
        20773,
        AsnClassification::DatacenterHosting,
        "Host Europe GmbH",
    ),
    entry(
        20940,
        AsnClassification::DatacenterHosting,
        "Akamai International",
    ),
    entry(
        20965,
        AsnClassification::EducationGov,
        "GEANT European Research Network",
    ),
    entry(
        21788,
        AsnClassification::DatacenterHosting,
        "Network Operations Center (Nocix)",
    ),
    entry(21859, AsnClassification::DatacenterHosting, "Zenlayer Inc."),
    entry(21928, AsnClassification::MobileCellular, "T-Mobile USA"),
    entry(
        22047,
        AsnClassification::IspResidential,
        "VTR Banda Ancha Chile",
    ),
    entry(
        22394,
        AsnClassification::MobileCellular,
        "Verizon Wireless Cellco",
    ),
    entry(
        22612,
        AsnClassification::DatacenterHosting,
        "Namecheap Hosting",
    ),
    entry(
        22773,
        AsnClassification::IspResidential,
        "Cox Communications US",
    ),
    entry(
        22822,
        AsnClassification::DatacenterHosting,
        "Limelight / Edgio Networks",
    ),
    entry(23028, AsnClassification::BusinessIsp, "Team Cymru"),
    entry(
        23033,
        AsnClassification::DatacenterHosting,
        "Wowrack Hosting",
    ),
    entry(
        23724,
        AsnClassification::DatacenterHosting,
        "China Telecom IDC",
    ),
    entry(
        23764,
        AsnClassification::BusinessIsp,
        "China Telecom CTGNet (CN2 GIA)",
    ),
    entry(
        23969,
        AsnClassification::IspResidential,
        "TOT Public Company Thailand",
    ),
    entry(24218, AsnClassification::BusinessIsp, "IIJ Japan"),
    entry(
        24348,
        AsnClassification::EducationGov,
        "CERNET2 China Education IPv6",
    ),
    entry(
        24429,
        AsnClassification::DatacenterHosting,
        "Alibaba / Taobao Cloud",
    ),
    entry(
        24560,
        AsnClassification::IspResidential,
        "Bharti Airtel India",
    ),
    entry(
        24940,
        AsnClassification::DatacenterHosting,
        "Hetzner Online GmbH",
    ),
    entry(
        24961,
        AsnClassification::DatacenterHosting,
        "myLoc Managed IT",
    ),
    entry(
        25019,
        AsnClassification::IspResidential,
        "STC Saudi Telecom",
    ),
    entry(
        25532,
        AsnClassification::DatacenterHosting,
        "Masterhost Cloud",
    ),
    entry(
        25820,
        AsnClassification::DatacenterHosting,
        "IT7 Networks (BandwagonHost)",
    ),
    entry(
        26496,
        AsnClassification::DatacenterHosting,
        "GoDaddy.com Hosting",
    ),
    entry(
        26599,
        AsnClassification::IspResidential,
        "Vivo / Telefonica Brasil",
    ),
    entry(28573, AsnClassification::IspResidential, "Claro Brasil"),
    entry(
        28753,
        AsnClassification::DatacenterHosting,
        "Leaseweb Deutschland",
    ),
    entry(
        29119,
        AsnClassification::DatacenterHosting,
        "ServiHosting Cloud",
    ),
    entry(
        29761,
        AsnClassification::DatacenterHosting,
        "QuadraNet Hosting",
    ),
    entry(
        29802,
        AsnClassification::DatacenterHosting,
        "HIVELOCITY Hosting",
    ),
    entry(
        30036,
        AsnClassification::IspResidential,
        "Mediacom Communications US",
    ),
    entry(
        30058,
        AsnClassification::DatacenterHosting,
        "FDCservers.net",
    ),
    entry(
        30083,
        AsnClassification::DatacenterHosting,
        "ServerCentral / Deft",
    ),
    entry(30633, AsnClassification::DatacenterHosting, "Leaseweb USA"),
    entry(30722, AsnClassification::MobileCellular, "Vodafone Italy"),
    entry(
        31034,
        AsnClassification::DatacenterHosting,
        "Aruba S.p.A. Cloud",
    ),
    entry(
        31334,
        AsnClassification::IspResidential,
        "Vodafone Kabel Deutschland",
    ),
    entry(
        31898,
        AsnClassification::DatacenterHosting,
        "Oracle Cloud Infrastructure (OCI)",
    ),
    entry(
        32244,
        AsnClassification::DatacenterHosting,
        "Liquid Web Hosting",
    ),
    entry(
        32475,
        AsnClassification::DatacenterHosting,
        "SingleHop / INAP Hosting",
    ),
    entry(32590, AsnClassification::BusinessIsp, "Valve Corporation"),
    entry(
        32787,
        AsnClassification::DatacenterHosting,
        "Akamai Prolexic",
    ),
    entry(
        32934,
        AsnClassification::DatacenterHosting,
        "Meta Platforms Infrastructure",
    ),
    entry(
        33070,
        AsnClassification::DatacenterHosting,
        "Rackspace Hosting",
    ),
    entry(
        33438,
        AsnClassification::DatacenterHosting,
        "StackPath / Highwinds",
    ),
    entry(35540, AsnClassification::DatacenterHosting, "OVH Hosting"),
    entry(
        35916,
        AsnClassification::DatacenterHosting,
        "Multacom Corporation",
    ),
    entry(
        36007,
        AsnClassification::DatacenterHosting,
        "Kamatera Cloud",
    ),
    entry(
        36040,
        AsnClassification::DatacenterHosting,
        "Google LLC Infrastructure",
    ),
    entry(
        36114,
        AsnClassification::DatacenterHosting,
        "Versatile Hosting",
    ),
    entry(
        36351,
        AsnClassification::DatacenterHosting,
        "IBM Cloud / SoftLayer",
    ),
    entry(
        36352,
        AsnClassification::DatacenterHosting,
        "ColoCrossing / RackNerd",
    ),
    entry(36384, AsnClassification::DatacenterHosting, "Google LLC"),
    entry(36385, AsnClassification::DatacenterHosting, "Google LLC"),
    entry(
        36647,
        AsnClassification::DatacenterHosting,
        "Yahoo Infrastructure",
    ),
    entry(
        36692,
        AsnClassification::DatacenterHosting,
        "Cisco OpenDNS / Umbrella",
    ),
    entry(
        37963,
        AsnClassification::DatacenterHosting,
        "Alibaba Cloud (Aliyun CN)",
    ),
    entry(38365, AsnClassification::DatacenterHosting, "Baidu Cloud"),
    entry(
        38895,
        AsnClassification::DatacenterHosting,
        "Amazon AWS APAC",
    ),
    entry(
        39351,
        AsnClassification::PublicProxyVpnTor,
        "31173 Services AB (Mullvad VPN)",
    ),
    entry(40021, AsnClassification::DatacenterHosting, "Contabo US"),
    entry(40509, AsnClassification::DatacenterHosting, "Fly.io Cloud"),
    entry(
        40676,
        AsnClassification::DatacenterHosting,
        "Psychz Networks",
    ),
    entry(
        43350,
        AsnClassification::DatacenterHosting,
        "NForce Entertainment",
    ),
    entry(
        44050,
        AsnClassification::DatacenterHosting,
        "Petersburg Internet Network VPS",
    ),
    entry(
        44477,
        AsnClassification::PublicProxyVpnTor,
        "Stark Industries Solutions (Proxy Pool)",
    ),
    entry(
        45090,
        AsnClassification::DatacenterHosting,
        "Tencent Cloud CN",
    ),
    entry(
        45102,
        AsnClassification::DatacenterHosting,
        "Alibaba Cloud (Aliyun Global)",
    ),
    entry(
        45103,
        AsnClassification::DatacenterHosting,
        "Alibaba Cloud Singapore",
    ),
    entry(
        45629,
        AsnClassification::IspResidential,
        "JasTel / 3BB Thailand",
    ),
    entry(
        45686,
        AsnClassification::MobileCellular,
        "Rakuten Mobile Japan",
    ),
    entry(
        45839,
        AsnClassification::DatacenterHosting,
        "Shinjiru Hosting Malaysia",
    ),
    entry(45899, AsnClassification::IspResidential, "VNPT Vietnam"),
    entry(
        46261,
        AsnClassification::DatacenterHosting,
        "QuickPacket Hosting",
    ),
    entry(
        46375,
        AsnClassification::IspResidential,
        "Sonic.net Fiber US",
    ),
    entry(
        46562,
        AsnClassification::DatacenterHosting,
        "Total Server Solutions / Performive",
    ),
    entry(
        46606,
        AsnClassification::DatacenterHosting,
        "Unified Layer / Bluehost",
    ),
    entry(
        46844,
        AsnClassification::DatacenterHosting,
        "Sharktech Hosting",
    ),
    entry(
        49505,
        AsnClassification::DatacenterHosting,
        "Selectel Cloud",
    ),
    entry(
        49544,
        AsnClassification::DatacenterHosting,
        "i3D.net Hosting",
    ),
    entry(
        49981,
        AsnClassification::DatacenterHosting,
        "WorldStream Hosting",
    ),
    entry(
        50673,
        AsnClassification::DatacenterHosting,
        "Serverius Holding",
    ),
    entry(51167, AsnClassification::DatacenterHosting, "Contabo GmbH"),
    entry(
        51396,
        AsnClassification::DatacenterHosting,
        "Pfcloud Hosting",
    ),
    entry(
        51852,
        AsnClassification::PublicProxyVpnTor,
        "Private Layer INC (VPN Pool)",
    ),
    entry(
        53667,
        AsnClassification::DatacenterHosting,
        "FranTech Solutions (BuyVM)",
    ),
    entry(54113, AsnClassification::DatacenterHosting, "Fastly Inc."),
    entry(
        54290,
        AsnClassification::DatacenterHosting,
        "Hostwinds Hosting",
    ),
    entry(54574, AsnClassification::DatacenterHosting, "DMIT Inc."),
    entry(
        54825,
        AsnClassification::DatacenterHosting,
        "Equinix Metal / Packet",
    ),
    entry(
        55286,
        AsnClassification::DatacenterHosting,
        "B2 Net Solutions (ServerMania)",
    ),
    entry(
        55430,
        AsnClassification::IspResidential,
        "MyRepublic Singapore",
    ),
    entry(
        55720,
        AsnClassification::DatacenterHosting,
        "Gigabit Hosting Malaysia",
    ),
    entry(
        55836,
        AsnClassification::MobileCellular,
        "Reliance Jio India",
    ),
    entry(55967, AsnClassification::DatacenterHosting, "Baidu Cloud"),
    entry(
        55990,
        AsnClassification::DatacenterHosting,
        "Huawei Cloud CN",
    ),
    entry(
        56040,
        AsnClassification::IspResidential,
        "China Mobile Guangdong",
    ),
    entry(
        56041,
        AsnClassification::IspResidential,
        "China Mobile Zhejiang",
    ),
    entry(
        56046,
        AsnClassification::IspResidential,
        "China Mobile Jiangsu",
    ),
    entry(
        56048,
        AsnClassification::IspResidential,
        "China Mobile Beijing",
    ),
    entry(
        57695,
        AsnClassification::DatacenterHosting,
        "Misaka Network",
    ),
    entry(
        58453,
        AsnClassification::BusinessIsp,
        "China Mobile International (CMI)",
    ),
    entry(
        58563,
        AsnClassification::IspResidential,
        "China Telecom Hubei",
    ),
    entry(
        58807,
        AsnClassification::DatacenterHosting,
        "Cloudie Limited HK",
    ),
    entry(
        59253,
        AsnClassification::DatacenterHosting,
        "Leaseweb Asia Pacific",
    ),
    entry(
        60068,
        AsnClassification::PublicProxyVpnTor,
        "Datacamp / CDN77 (Shared Proxy Pool)",
    ),
    entry(
        60781,
        AsnClassification::DatacenterHosting,
        "Leaseweb Netherlands",
    ),
    entry(
        62240,
        AsnClassification::DatacenterHosting,
        "Clouvider Limited",
    ),
    entry(
        62371,
        AsnClassification::PublicProxyVpnTor,
        "Proton AG (ProtonVPN)",
    ),
    entry(
        62567,
        AsnClassification::DatacenterHosting,
        "DigitalOcean NYC",
    ),
    entry(
        62744,
        AsnClassification::DatacenterHosting,
        "Quintex Alliance",
    ),
    entry(
        62904,
        AsnClassification::DatacenterHosting,
        "Eonix Corporation",
    ),
    entry(
        63018,
        AsnClassification::DatacenterHosting,
        "US Dedicated Hosting",
    ),
    entry(
        63150,
        AsnClassification::DatacenterHosting,
        "BageVM Hosting",
    ),
    entry(
        63473,
        AsnClassification::DatacenterHosting,
        "HostHatch Hosting",
    ),
    entry(
        63949,
        AsnClassification::DatacenterHosting,
        "Akamai Connected Cloud (Linode)",
    ),
    entry(
        131199,
        AsnClassification::DatacenterHosting,
        "Kagoya Japan Cloud",
    ),
    entry(
        132199,
        AsnClassification::IspResidential,
        "Globe Telecom Philippines",
    ),
    entry(
        132203,
        AsnClassification::DatacenterHosting,
        "Tencent Cloud Global",
    ),
    entry(
        132525,
        AsnClassification::DatacenterHosting,
        "Tencent Cloud",
    ),
    entry(
        132591,
        AsnClassification::DatacenterHosting,
        "Cloud Innovation Hosting",
    ),
    entry(
        132892,
        AsnClassification::DatacenterHosting,
        "Cloudflare APAC",
    ),
    entry(
        133119,
        AsnClassification::BusinessIsp,
        "China Telecom Global",
    ),
    entry(
        133165,
        AsnClassification::DatacenterHosting,
        "DigitalOcean Singapore",
    ),
    entry(
        133612,
        AsnClassification::IspResidential,
        "Aussie Broadband Australia",
    ),
    entry(
        133752,
        AsnClassification::DatacenterHosting,
        "Leaseweb / Cloudie HK",
    ),
    entry(
        134450,
        AsnClassification::DatacenterHosting,
        "CloudSigma Cloud",
    ),
    entry(
        135330,
        AsnClassification::DatacenterHosting,
        "GreenCloudVPS",
    ),
    entry(
        135377,
        AsnClassification::DatacenterHosting,
        "UCloud Global",
    ),
    entry(
        136787,
        AsnClassification::PublicProxyVpnTor,
        "PacketHub / Shared VPN Pool",
    ),
    entry(
        136907,
        AsnClassification::DatacenterHosting,
        "Huawei Cloud International",
    ),
    entry(
        137718,
        AsnClassification::DatacenterHosting,
        "ByteDance / Volcano Engine",
    ),
    entry(
        138062,
        AsnClassification::PublicProxyVpnTor,
        "Akari Networks (Shared Proxy Pool)",
    ),
    entry(
        138384,
        AsnClassification::MobileCellular,
        "Rakuten Mobile Japan",
    ),
    entry(
        138915,
        AsnClassification::PublicProxyVpnTor,
        "Akari Networks (Shared Proxy Pool)",
    ),
    entry(
        138997,
        AsnClassification::DatacenterHosting,
        "Eons Data Communications",
    ),
    entry(
        139007,
        AsnClassification::DatacenterHosting,
        "Misaka Network",
    ),
    entry(
        139341,
        AsnClassification::DatacenterHosting,
        "Alibaba Cloud Singapore (ACE)",
    ),
    entry(
        140096,
        AsnClassification::DatacenterHosting,
        "Hytron Network",
    ),
    entry(
        140292,
        AsnClassification::DatacenterHosting,
        "Alibaba Cloud",
    ),
    entry(141995, AsnClassification::DatacenterHosting, "Contabo Asia"),
    entry(197540, AsnClassification::DatacenterHosting, "Netcup GmbH"),
    entry(
        197695,
        AsnClassification::DatacenterHosting,
        "REG.RU Hosting",
    ),
    entry(
        198605,
        AsnClassification::PublicProxyVpnTor,
        "Avast / Gen Digital VPN",
    ),
    entry(199524, AsnClassification::DatacenterHosting, "G-Core Labs"),
    entry(
        200130,
        AsnClassification::DatacenterHosting,
        "DigitalOcean Europe",
    ),
    entry(
        202018,
        AsnClassification::DatacenterHosting,
        "DigitalOcean London",
    ),
    entry(
        202053,
        AsnClassification::DatacenterHosting,
        "UpCloud Hosting",
    ),
    entry(
        202109,
        AsnClassification::DatacenterHosting,
        "DigitalOcean Frankfurt",
    ),
    entry(202422, AsnClassification::DatacenterHosting, "G-Core Labs"),
    entry(
        202425,
        AsnClassification::PublicProxyVpnTor,
        "IP Volume Inc (Proxy Pool)",
    ),
    entry(
        205714,
        AsnClassification::IspResidential,
        "Hyperoptic UK Broadband",
    ),
    entry(
        206092,
        AsnClassification::PublicProxyVpnTor,
        "IPXO Shared Proxy Pool",
    ),
    entry(
        206264,
        AsnClassification::DatacenterHosting,
        "Amarutu Technology Hosting",
    ),
    entry(
        208091,
        AsnClassification::PublicProxyVpnTor,
        "Private Layer VPN Pool",
    ),
    entry(
        209103,
        AsnClassification::PublicProxyVpnTor,
        "Proton AG (ProtonVPN)",
    ),
    entry(
        209242,
        AsnClassification::DatacenterHosting,
        "Cloudflare London",
    ),
    entry(
        209366,
        AsnClassification::DatacenterHosting,
        "Serverius Hosting",
    ),
    entry(
        209588,
        AsnClassification::DatacenterHosting,
        "Fly.io Infrastructure",
    ),
    entry(
        209854,
        AsnClassification::DatacenterHosting,
        "Cyber Assets Hosting",
    ),
    entry(
        210558,
        AsnClassification::PublicProxyVpnTor,
        "1337 Services / Njalla VPN",
    ),
    entry(
        210644,
        AsnClassification::DatacenterHosting,
        "AEZA Group Hosting",
    ),
    entry(
        211252,
        AsnClassification::DatacenterHosting,
        "Delis LLC Hosting",
    ),
    entry(
        212238,
        AsnClassification::PublicProxyVpnTor,
        "Datacamp Limited (Shared Proxy/VPN Pool)",
    ),
    entry(
        212317,
        AsnClassification::DatacenterHosting,
        "Hetzner Cloud Finland",
    ),
    entry(
        213230,
        AsnClassification::DatacenterHosting,
        "Hetzner Cloud",
    ),
    entry(
        393406,
        AsnClassification::DatacenterHosting,
        "DigitalOcean San Francisco",
    ),
    entry(
        394161,
        AsnClassification::DatacenterHosting,
        "Render.com Cloud",
    ),
    entry(
        396356,
        AsnClassification::DatacenterHosting,
        "Maxihost / Latitude.sh",
    ),
    entry(396982, AsnClassification::DatacenterHosting, "Google Cloud"),
    entry(
        396986,
        AsnClassification::DatacenterHosting,
        "ByteDance US Cloud",
    ),
    entry(
        398101,
        AsnClassification::DatacenterHosting,
        "GoDaddy Cloud",
    ),
    entry(
        398324,
        AsnClassification::DatacenterHosting,
        "Censys Infrastructure",
    ),
    entry(
        398722,
        AsnClassification::DatacenterHosting,
        "Censys Infrastructure",
    ),
    entry(
        399471,
        AsnClassification::DatacenterHosting,
        "Vultr / Constant Hosting",
    ),
    entry(399804, AsnClassification::DatacenterHosting, "Spartan Host"),
];

/// Returns total number of embedded ASN entries.
pub const fn known_asn_count() -> usize {
    KNOWN_ASNS.len()
}

/// Binary-searches [`KNOWN_ASNS`] and returns the full static [`AsnEntry`] when known.
pub fn lookup_asn_entry(asn: u32) -> Option<&'static AsnEntry> {
    KNOWN_ASNS
        .binary_search_by_key(&asn, |e| e.asn)
        .ok()
        .map(|idx| &KNOWN_ASNS[idx])
}

/// Looks up an ASN in the embedded offline table, returning `(AsnClassification, org_name)`.
pub fn lookup_asn(asn: u32) -> Option<(AsnClassification, &'static str)> {
    lookup_asn_entry(asn).map(|e| (e.classification, e.org))
}

/// Classifies an ASN, falling back to `(AsnClassification::Unknown, "Unknown ASN")` when absent.
pub fn classify_asn(asn: u32) -> (AsnClassification, &'static str) {
    lookup_asn(asn).unwrap_or((AsnClassification::Unknown, "Unknown ASN"))
}

/// Returns `true` when `asn` belongs to a known high-abuse shared proxy / commercial VPN exit pool.
pub fn is_high_abuse_proxy_asn(asn: u32) -> bool {
    lookup_asn_entry(asn).is_some_and(|e| e.high_abuse_proxy_pool)
}

/// Heuristic fallback classifier for ASN organization names when an ASN is not in [`KNOWN_ASNS`].
pub fn classify_org_heuristic(org: &str) -> AsnClassification {
    let lower = org.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return AsnClassification::Unknown;
    }

    const PROXY_VPN_HINTS: &[&str] = &[
        "m247",
        "datacamp",
        "mullvad",
        "proton",
        "nordvpn",
        "expressvpn",
        "surfshark",
        "tor exit",
        "tor project",
        "vpn",
        "proxy",
        "private layer",
        "packethub",
        "stark industries",
        "njalla",
    ];
    if PROXY_VPN_HINTS.iter().any(|kw| lower.contains(kw)) {
        return AsnClassification::PublicProxyVpnTor;
    }

    const DATACENTER_HINTS: &[&str] = &[
        "amazon",
        "aws",
        "google cloud",
        "microsoft",
        "azure",
        "oracle",
        "digitalocean",
        "vultr",
        "choopa",
        "linode",
        "akamai",
        "hetzner",
        "ovh",
        "cloudflare",
        "dmit",
        "bandwagon",
        "it7",
        "racknerd",
        "colocrossing",
        "alibaba",
        "aliyun",
        "tencent",
        "huawei cloud",
        "scaleway",
        "contabo",
        "leaseweb",
        "fastly",
        "g-core",
        "kamatera",
        "upcloud",
        "buyvm",
        "frantech",
        "hosthatch",
        "netcup",
        "ionos",
        "rackspace",
        "softlayer",
        "equinix",
        "zenlayer",
        "misaka",
        "hytron",
        "hosting",
        "datacenter",
        "data center",
        "server",
        "cloud",
        "vps",
        "colocation",
    ];
    if DATACENTER_HINTS.iter().any(|kw| lower.contains(kw)) {
        return AsnClassification::DatacenterHosting;
    }

    const EDU_GOV_HINTS: &[&str] = &[
        "university",
        "college",
        "institute of technology",
        "academic",
        "research",
        "cernet",
        "government",
        "ministry",
        "school",
    ];
    if EDU_GOV_HINTS.iter().any(|kw| lower.contains(kw)) {
        return AsnClassification::EducationGov;
    }

    const MOBILE_HINTS: &[&str] = &[
        "wireless", "cellular", "mobility", "t-mobile", "docomo", "mobile",
    ];
    if MOBILE_HINTS.iter().any(|kw| lower.contains(kw)) {
        return AsnClassification::MobileCellular;
    }

    const RESIDENTIAL_HINTS: &[&str] = &[
        "comcast",
        "xfinity",
        "at&t",
        "verizon",
        "charter",
        "spectrum",
        "cox communications",
        "frontier",
        "google fiber",
        "starlink",
        "broadband",
        "cable",
        "fiber",
        "fibre",
        "telecom",
        "telekom",
        "telecommunications",
        "singtel",
        "starhub",
        "softbank",
        "kddi",
        "ntt",
        "chunghwa",
        "hinet",
        "telstra",
        "optus",
        "virgin media",
        "british telecomm",
        "orange",
        "swisscom",
        "telia",
        "telenor",
    ];
    if RESIDENTIAL_HINTS.iter().any(|kw| lower.contains(kw)) {
        return AsnClassification::IspResidential;
    }

    AsnClassification::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_strictly_sorted_unique_and_exceeds_200_entries() {
        assert!(
            KNOWN_ASNS.len() >= 200,
            "expected >= 200 embedded ASNs, found {}",
            KNOWN_ASNS.len()
        );
        for pair in KNOWN_ASNS.windows(2) {
            assert!(
                pair[0].asn < pair[1].asn,
                "KNOWN_ASNS out of order or duplicate: AS{} >= AS{}",
                pair[0].asn,
                pair[1].asn
            );
            assert!(!pair[0].org.is_empty());
        }
        assert!(!KNOWN_ASNS.last().unwrap().org.is_empty());
    }

    #[test]
    fn classifies_required_cloud_vps_proxy_and_residential_asns() {
        // Cloud / VPS / Datacenters
        for (asn, expected_substr) in [
            (16509, "Amazon"),
            (14618, "Amazon"),
            (15169, "Google"),
            (396982, "Google"),
            (8075, "Azure"),
            (31898, "Oracle"),
            (14061, "DigitalOcean"),
            (20473, "Vultr"),
            (63949, "Linode"),
            (24940, "Hetzner"),
            (16276, "OVH"),
            (13335, "Cloudflare"),
            (54574, "DMIT"),
            (906, "DMIT"),
            (25820, "Bandwagon"),
            (36352, "RackNerd"),
            (45102, "Aliyun"),
            (132203, "Tencent"),
            (136907, "Huawei"),
        ] {
            let (class, org) = lookup_asn(asn).unwrap_or_else(|| panic!("missing AS{asn}"));
            assert_eq!(
                class,
                AsnClassification::DatacenterHosting,
                "AS{asn} ({org}) should be DatacenterHosting"
            );
            assert!(
                org.contains(expected_substr),
                "AS{asn} org '{org}' missing '{expected_substr}'"
            );
        }

        // High-abuse proxy/VPN pools
        for asn in [9009, 212238, 138915, 39351, 209103] {
            let (class, _) = classify_asn(asn);
            assert_eq!(class, AsnClassification::PublicProxyVpnTor);
            assert!(is_high_abuse_proxy_asn(asn));
        }

        // Major residential ISPs
        for asn in [
            7922, 7018, 701, 20115, 4713, 2516, 17676, 2856, 3320, 7473, 4657, 3462, 4760,
        ] {
            let (class, _) = lookup_asn(asn).unwrap_or_else(|| panic!("missing ISP AS{asn}"));
            assert_eq!(
                class,
                AsnClassification::IspResidential,
                "AS{asn} should be IspResidential"
            );
            assert!(!is_high_abuse_proxy_asn(asn));
        }

        // Unknown ASN fallback
        assert_eq!(lookup_asn(999_999), None);
        assert_eq!(
            classify_asn(999_999),
            (AsnClassification::Unknown, "Unknown ASN")
        );
    }

    #[test]
    fn org_heuristic_classifies_unlisted_providers() {
        assert_eq!(
            classify_org_heuristic("Amazon Data Services JP"),
            AsnClassification::DatacenterHosting
        );
        assert_eq!(
            classify_org_heuristic("M247 Global VPN Transit"),
            AsnClassification::PublicProxyVpnTor
        );
        assert_eq!(
            classify_org_heuristic("Comcast Cable Communications"),
            AsnClassification::IspResidential
        );
        assert_eq!(
            classify_org_heuristic("T-Mobile Wireless Corp"),
            AsnClassification::MobileCellular
        );
        assert_eq!(
            classify_org_heuristic("Example University Network"),
            AsnClassification::EducationGov
        );
        assert_eq!(
            classify_org_heuristic("Equinix Colocation Services"),
            AsnClassification::DatacenterHosting
        );
        assert_ne!(
            classify_org_heuristic("ETB Colombia Telecom ISP"),
            AsnClassification::DatacenterHosting
        );
        assert_ne!(
            classify_org_heuristic("Colorado Broadband Communications"),
            AsnClassification::DatacenterHosting
        );
        assert_eq!(classify_org_heuristic(""), AsnClassification::Unknown);
    }
}
