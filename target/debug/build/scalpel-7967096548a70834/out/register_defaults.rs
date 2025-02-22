use std::sync::Once;

static INIT: Once = Once::new();

/// Register Default protocol handlers.
///
/// Each [`Layer`][`crate::layer::Layer`] in `scalpel` will be decoded by a certain field in the
/// lower layer for which this particular layer is a payload. For example, [`ipv4::IPv4`] is a
/// payload for [`ethernet::Ethernet`]. Thus while decoding a particular layer, the next layer to
/// be decoded is determined by a value of certain field in the current layer. In the example
/// above, EtherType in the Ethernet header determines the next layer (EtherType: 0x8000
/// corresponds to [`ipv4::IPv4`]).
///
/// To initialize the dissection framework properly, the application should call this function
/// before trying to dissect packets. If this function is not called, all the data is shown as
/// `unprocessed` data in the [`Packet`][`crate::Packet`]
///
/// ```rust
/// # fn main() {
///
/// let _ = scalpel::register_defaults();
///
/// let packet_data =
/// hex::decode("000573a007d168a3c4f949f686dd600000000020064020010470e5bfdead49572174e82c48872607f8b0400c0c03000000000000001af9c7001903a088300000000080022000da4700000204058c0103030801010402").unwrap();
///
/// let packet = scalpel::Packet::from_bytes(&packet_data, scalpel::ENCAP_TYPE_ETH);
///
/// eprintln!("Packet: {:#?}", packet);
///
/// # }
///
/// ```
///
/// In this function we just call the `register_defaults` functions for each of the currently
/// supported layers.
///
/// When a new layer is defined outside the crate, that particular layer may use a `register_*`
/// function in it's upper layer to request it's dissection. This glues all the dissectors for the
/// layers together.

pub fn register_defaults() -> Result<(), crate::errors::Error> {
    let mut result: Result<(), crate::errors::Error> = Ok(());

    fn inner() -> Result<(), crate::errors::Error> {
        // We need to make sure `packet::register_defaults` is initialized first.
        crate::packet::register_defaults()?;

        // Now all the layers' `register_defaults`
        arp::register_defaults()?;
        ethernet::register_defaults()?;
        icmp::register_defaults()?;
        mpls::register_defaults()?;
        icmpv6::register_defaults()?;
        ipv6::register_defaults()?;
        linux_sll2::register_defaults()?;
        linux_sll::register_defaults()?;
        m3ua::register_defaults()?;
        sctp::register_defaults()?;
        tcp::register_defaults()?;
        vxlan::register_defaults()?;
        udp::register_defaults()?;
        ipv4::register_defaults()?;
        dns::register_defaults()?;

        Ok(())
    }

    INIT.call_once(|| {
        result = inner();

        if let Err(ref e) = result {
            #[cfg(feature = "logging")]
            log::error!("Error during register_defaults: {:#?}", e);

            eprintln!("Error : {:#?}", e);
        }
    });

    result
}
