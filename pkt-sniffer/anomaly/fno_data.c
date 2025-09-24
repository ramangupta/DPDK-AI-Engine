#include "futures_options.h"

// ------------------------------------------------------------------
// Master per-symbol mapping (support & resistance default = 0.0)
// ------------------------------------------------------------------

fno_symbol_t FNO_SYMBOLS[] = {
    // Indices
    { "NIFTY",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_INDEX },
    { "BANKNIFTY",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_INDEX },

    // Auto / Auto Sector
    { "BAJAJ-AUTO",     .support=8980, .resistance=9430, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "BHARATFORG",     .support=1200, .resistance=1280, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "BOSCHLTD",       .support=38900, .resistance=41800, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "EICHERMOT",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "EXIDEIND",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "HEROMOTOCO",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "M&M",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "MARUTI",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "MOTHERSON",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "SONACOMS",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "TATAMOTORS",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "TIINDIA",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "TVSMOTOR",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },
    { "UNOMINDA",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_AUTO_SECTOR },

    // Capital Goods & Construction
    { "ABB",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "APLAPOLLO",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "ASHOKLEY",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "ASTRAL",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "BDL",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "BEL",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "BHEL",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "CGPOWER",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "CUMMINSIND",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "HAL",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "INOXWIND",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "KAYNES",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "KEI",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "MAZDOCK",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "POLYCAB",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "SIEMENS",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "SUPREMEIND",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "SUZLON",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    { "TITAGARH",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CAPITAL_GOODS },
    
    // Chemicals
    { "PIDILITIND",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CHEMICALS },
    { "PIIND",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CHEMICALS },
    { "SOLARINDS",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CHEMICALS },
    { "SRF",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CHEMICALS },
    { "TATACHEM",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CHEMICALS },
    { "UPL",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CHEMICALS },

    // Construction
    { "LT",             .support=274, .resistance=294, .category=FNO_CATEGORY_CONSTRUCTION },
    { "RVNL",           .support=274, .resistance=294, .category=FNO_CATEGORY_CONSTRUCTION },
    { "NBCC",           .support=274, .resistance=294, .category=FNO_CATEGORY_CONSTRUCTION },
    { "NCC",            .support=274, .resistance=294, .category=FNO_CATEGORY_CONSTRUCTION },

    // Construction Materials
    { "AMBUJACEM",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSTRUCTION_MATERIALS },
    { "DALBHARAT",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSTRUCTION_MATERIALS },
    { "GRASIM",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSTRUCTION_MATERIALS },
    { "SHREECEM",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSTRUCTION_MATERIALS },
    { "ULTRACEMCO",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSTRUCTION_MATERIALS },

    // Consumer Durables
    { "AMBER",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "ASIANPAINT",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "BLUESTARCO",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "CROMPTON",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "DIXON",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "HAVELLS",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "KALYANKJIL",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "PGEL",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "TITAN",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    { "VOLTAS",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_DURABLES },
    
    // Consumer Services
    { "DMART",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_SERVICES },
    { "ETERNAL",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_SERVICES },
    { "INDHOTEL",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_SERVICES },
    { "IRCTC",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_SERVICES },
    { "JUBLFOOD",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_SERVICES },
    { "NAUKRI",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_SERVICES },
    { "NYKAA",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_SERVICES },
    { "TRENT",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_CONSUMER_SERVICES },
    
    // FMCG
    { "BRITANNIA",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "COLPAL",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "DABUR",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "GODREJCP",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "HINDUNILVR",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "ITC",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "MARICO",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "NESTLEIND",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "PATANJALI",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "TATACONSUM",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "UNITDSPR",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    { "VBL",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_FMCG },
    
    // Financial Services - Private Banks
    { "AXISBANK",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "BANDHANBNK",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "FEDERALBNK",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "HDFCBANK",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "ICICIBANK",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "IDFCFIRSTB",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "INDUSINDBK",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "KOTAKBANK",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "RBLBANK",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },
    { "YESBANK",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PRIVATE_BANKING },

    // Financial Services - Public Banks
    { "BANKBARODA",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PUBLIC_BANKING },
    { "BANKINDIA",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PUBLIC_BANKING },
    { "CANBK",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PUBLIC_BANKING },
    { "INDIANB",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PUBLIC_BANKING },
    { "PNB",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PUBLIC_BANKING },
    { "SBIN",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PUBLIC_BANKING },
    { "UNIONBANK",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_PUBLIC_BANKING },
    
    // Financial Services
    { "360ONE",         .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "ABCAPITAL",      .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "ANGELONE",       .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "AUBANK",         .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "BAJAJFINSV",     .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "BAJFINANCE",     .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "BSE",            .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "CAMS",           .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "CDSL",           .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "CHOLAFIN",       .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "HDFCAMC",        .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "HDFCLIFE",       .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "HUDCO",          .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "ICICIGI",        .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "ICICIPRULI",     .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "IEX",            .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "IIFL",           .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "IREDA",          .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "IRFC",           .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "JIOFIN",         .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "KFINTECH",       .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "LICHSGFIN",      .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "LICI",           .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "LTF",            .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "MANAPPURAM",     .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "MCX",            .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "MFSL",           .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "MUTHOOTFIN",     .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "NUVAMA",         .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "PAYTM",          .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "PFC",            .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "PNBHOUSING",     .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "POLICYBZR",      .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "RECLTD",         .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "SAMMAANCAP",     .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "SBICARD",        .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "SBILIFE",        .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
    { "SHRIRAMFIN",     .support=274, .resistance=294, .category=FNO_CATEGORY_FINANCIAL_SERVICES },
   
    // Healthcare
    { "ALKEM",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "APOLLOHOSP",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "AUROPHARMA",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "BIOCON",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "CIPLA",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "DIVISLAB",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "DRREDDY",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "FORTIS",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "GLENMARK",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "LAURUSLABS",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "LUPIN",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "MANKIND",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "MAXHEALTH",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "PPLPHARMA",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "SUNPHARMA",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "SYNGENE",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "TORNTPHARM",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
    { "ZYDUSLIFE",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_HEALTHCARE },
 
    // Information Technology / IT
    { "COFORGE",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "CYIENT",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "HCLTECH",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "INFY",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "KPITTECH",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "LTIM",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "MPHASIS",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "OFSS",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "PERSISTENT",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "TATAELXSI",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "TATATECH",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "TCS",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "TECHM",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },
    { "WIPRO",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_IT },

    // Metals and Mining
    { "ADANIENT",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "HINDALCO",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "HINDZINC",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "JINDALSTEL",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "JSWSTEEL",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "NATIONALUM",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "NMDC",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "SAIL",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "TATASTEEL",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },
    { "VEDL",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_METALS_AND_MINING },

    // Oig Gas and COnsumable Fuels
    { "BPCL",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "COALINDIA",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "GAIL",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "HINDPETRO",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "IGL",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "IOC",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "OIL",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "ONGC",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "PETRONET",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },
    { "RELIANCE",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_OIL_AND_GAS },

    // Power
    { "ADANIENSOL",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_POWER },
    { "ADANIGREEN",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_POWER },
    { "JSWENERGY",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_POWER },
    { "NHPC",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_POWER },
    { "NTPC",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_POWER },
    { "POWERGRID",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_POWER },
    { "TATAPOWER",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_POWER },
    { "TORNTPOWER",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_POWER },
    
    // Realty / Real Estate
    { "DLF",            .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_REALTY },
    { "LODHA",          .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_REALTY },
    { "PRESTIGE",       .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_REALTY },
    { "GODREJPROP",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_REALTY },
    { "OBEROIRLTY",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_REALTY },
    { "PHOENIXLTD",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_REALTY },

    // Services
    { "ADANIPORTS",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_SERVICES },
    { "INDIGO",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_SERVICES },  
    { "GMRAIRPORT",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_SERVICES },  
    { "CONCOR",         .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_SERVICES },  
    { "DELHIVERY",      .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_SERVICES }, 
    
    // Telecommunications
    { "BHARTIARTL",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_TELECOM },
    { "HFCL",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_TELECOM },
    { "IDEA",           .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_TELECOM },
    { "INDUSTOWER",     .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_TELECOM },
    
    // Textiles
    { "PAGEIND",        .support=0.0, .resistance=0.0, .category=FNO_CATEGORY_TEXTILES }
};

const size_t FNO_SYMBOL_COUNT = sizeof(FNO_SYMBOLS) / sizeof(FNO_SYMBOLS[0]);
