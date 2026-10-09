fn main() -> Result<(), Box<dyn std::error::Error>> {
    streamscope_plugin_host::serve_with_progress(|action, input, progress| streamscope_plugin_media::execute("pcap", action, input, progress))?;
    Ok(())
}
