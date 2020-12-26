mod error;

mod engine;
use engine::*;

mod mapper;
use mapper::*;

use std::cell::RefCell;
use std::rc::Rc;

use clap::*;
use log::{info, Level};

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

fn main() {
    let matches = App::new("dump offsets example")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("verbose").short("v").multiple(true))
        .arg(
            Arg::with_name("connector")
                .long("connector")
                .short("c")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("args")
                .long("args")
                .short("a")
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::with_name("collectors")
                .long("collectors")
                .short("col")
                .takes_value(true)
                .use_delimiter(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .long("output")
                .short("o")
                .takes_value(true),
        )
        .get_matches();

    // set log level
    let level = match matches.occurrences_of("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        4 => Level::Trace,
        _ => Level::Trace,
    };
    simple_logger::SimpleLogger::new()
        .with_level(level.to_level_filter())
        .init()
        .unwrap();

    let collectors = matches.values_of("collectors").unwrap().collect::<Vec<_>>();

    // create inventory + connector
    let inventory = unsafe { ConnectorInventory::scan() };
    let connector = unsafe {
        inventory.create_connector(
            matches.value_of("connector").unwrap(),
            &ConnectorArgs::parse(matches.value_of("args").unwrap()).unwrap(),
        )
    }
    .unwrap();

    // find ntoskrnl
    let mut kernel = Kernel::builder(connector)
        .build_default_caches()
        .build()
        .unwrap();

    // find csgo.exe
    let process_info = kernel
        .process_info("csgo.exe")
        .expect("unable to find csgo.exe process");
    let mut process = Win32Process::with_kernel(kernel, process_info);
    info!("found process: {:?}", process);

    // TODO: add all required modules here (engine.dll, client.dll, etc)
    let module_info = process.module_info("csgo.exe").unwrap();
    info!("found module: {:?}", module_info);

    // create engine managers
    info!("parsing interfaces");
    let interface_manager =
        InterfaceManager::new(&mut process).expect("unable to parse engine interfaces");
    info!("parsing recvprops");
    let recvprop_manager = RecvPropManager::new(&mut process, &interface_manager)
        .expect("unable to parse recv tables");
    info!("parsing convars");
    let cvar_manager =
        CVarManager::new(&mut process, &interface_manager).expect("unable to parse convars");

    // TODO: specify scanners via cmdline args and dynamically add them to the function mapper
    // TODO: scan interfaces, recvprops, etc
    let mut functions = Vec::new();

    if collectors.iter().find(|&&c| c == "interfaces").is_some() {
        info!("scanning interfaces");
        let mut interfaces = InterfaceCollector::new(process.clone(), &interface_manager);
        functions.append(&mut interfaces.collect().unwrap());
    }

    if collectors.iter().find(|&&c| c == "recvprops").is_some() {
        info!("scanning recvprops");
        let mut recvprops =
            RecvPropCollector::new(process.clone(), &interface_manager, &recvprop_manager);
        functions.append(&mut recvprops.collect().unwrap());
    }

    if collectors.iter().find(|&&c| c == "cvars").is_some() {
        //info!("scanning cvars");
        //let mut recvprops = RecvPropCollector::new(&interface_manager, &recvprop_manager);
        //functions.append(&mut recvprops.collect().unwrap()); // TODO:
    }

    // feed the mapper with our potential functions
    let mut mapper = mapper::FunctionMapper::new(functions);
    mapper.map_out_code(&mut process);
}
