use std::io;
use std::path::{Path, PathBuf};

use grep2::matcher::Matcher;
use grep2::printer::{JSON, Standard, Summary, Stats};
use grep2::searcher::Searcher;
use termcolor::WriteColor;

use decompressor::{DecompressionReader, is_compressed};
use preprocessor::PreprocessorReader;
use subject::Subject;

/// The configuration for the search worker. Among a few other things, the
/// configuration primarily controls the way we show search results to users
/// at a very high level.
#[derive(Clone, Debug)]
struct Config {
    preprocessor: Option<PathBuf>,
    search_zip: bool,
    separator_file: Option<Vec<u8>>,
    stats: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            preprocessor: None,
            search_zip: false,
            separator_file: None,
            stats: false,
        }
    }
}

/// A builder for configuring and constructing a search worker.
#[derive(Clone, Debug)]
pub struct SearchWorkerBuilder {
    config: Config,
}

impl Default for SearchWorkerBuilder {
    fn default() -> SearchWorkerBuilder {
        SearchWorkerBuilder::new()
    }
}

impl SearchWorkerBuilder {
    /// Create a new builder for configuring and constructing a search worker.
    pub fn new() -> SearchWorkerBuilder {
        SearchWorkerBuilder { config: Config::default() }
    }

    /// Create a new search worker using the given searcher, matcher and
    /// printer.
    pub fn build<M, W>(
        &self,
        searcher: Searcher,
        matcher: M,
        printer: Printer<W>,
    ) -> SearchWorker<M, W>
    where M: Matcher,
          W: WriteColor
    {
        let config = self.config.clone();
        let stats = if config.stats { Some(Stats::new()) } else { None };
        SearchWorker { config, searcher, matcher, printer, stats, count: 0 }
    }

    /// Set the path to a preprocessor command.
    ///
    /// When this is set, instead of searching files directly, the given
    /// command will be run with the file path as the first argument, and the
    /// output of that command will be searched instead.
    pub fn preprocessor(
        &mut self,
        cmd: Option<PathBuf>,
    ) -> &mut SearchWorkerBuilder {
        self.config.preprocessor = cmd;
        self
    }

    /// Enable the decompression and searching of common compressed files.
    ///
    /// When enabled, if a particular file path is recognized as a compressed
    /// file, then it is decompressed before searching.
    ///
    /// Note that if a preprocessor command is set, then it overrides this
    /// setting.
    pub fn search_zip(&mut self, yes: bool) -> &mut SearchWorkerBuilder {
        self.config.search_zip = yes;
        self
    }

    /// Associate a file separator with this search worker.
    ///
    /// A search worker will not, on its own, emit a file separator
    /// automatically. Instead, a search worker provides a
    /// `write_separator_file` method that, when called, will print the given
    /// file separator if and only if a previous search printed at least one
    /// byte and the standard printer is in use.
    pub fn separator_file(
        &mut self,
        separator: Option<Vec<u8>>,
    ) -> &mut SearchWorkerBuilder {
        self.config.separator_file = separator;
        self
    }

    /// Compute statistics when enabled. This includes, but is not limited to,
    /// the total number of matches, the number of bytes searched and more.
    ///
    /// When statistics are computed, they are included in the results of every
    /// search.
    pub fn stats(&mut self, yes: bool) -> &mut SearchWorkerBuilder {
        self.config.stats = yes;
        self
    }
}

/// The result of executing a search.
///
/// Generally speaking, the "result" of a search is sent to a printer, which
/// writes results to an underlying writer such as stdout or a file. However,
/// every search also has some aggregate statistics or meta data that may be
/// useful to higher level routines.
#[derive(Clone, Debug, Default)]
pub struct SearchResult {
    nth: u64,
    has_match: bool,
    binary_byte_offset: Option<u64>,
    stats: Option<Stats>,
}

impl SearchResult {
    /// Returns the sequence number of this search. i.e., "This result
    /// corresponds to the `nth` search performed by this worker."
    pub fn nth(&self) -> u64 {
        self.nth
    }

    /// Whether the search found a match or not.
    pub fn has_match(&self) -> bool {
        self.has_match
    }

    /// Whether the search found binary data, and if so, the first absolute
    /// byte offset at which it was detected.
    ///
    /// This always returns `None` if binary data detection is disabled, even
    /// when binary data is present.
    pub fn binary_byte_offset(&self) -> Option<u64> {
        self.binary_byte_offset
    }

    /// Return aggregate search statistics, if available.
    ///
    /// It can be expensive to compute statistics, so these are only present
    /// if explicitly enabled in the printer provided by the caller.
    pub fn stats(&self) -> Option<&Stats> {
        self.stats.as_ref()
    }
}

/// The printer used by a search worker.
///
/// The `W` type parameter refers to the type of the underlying writer.
#[derive(Debug)]
pub enum Printer<W> {
    /// Use the standard printer, which supports the classic grep-like format.
    Standard(Standard<W>),
    /// Use the summary printer, which supports aggregate displays of search
    /// results.
    Summary(Summary<W>),
    /// A JSON printer, which emits results in the JSON Lines format.
    JSON(JSON<W>),
}

impl<W> Printer<W> {
    /// Returns true if and only if the printer has written at least one byte.
    fn has_written(&self) -> bool {
        match *self {
            Printer::Standard(ref p) => p.has_written(),
            Printer::Summary(ref p) => p.has_written(),
            Printer::JSON(ref p) => p.has_written(),
        }
    }
}

/// A worker for executing searches.
///
/// It is intended for a single worker to execute many searches, and is
/// generally intended to be used from a single thread. When searching using
/// multiple threads, it is better to create a new worker for each thread.
#[derive(Debug)]
pub struct SearchWorker<M, W> {
    config: Config,
    searcher: Searcher,
    matcher: M,
    printer: Printer<W>,
    stats: Option<Stats>,
    count: u64,
}

impl<M: Matcher, W: WriteColor> SearchWorker<M, W> {
    /// Execute a search over the given subject.
    pub fn search(&mut self, subject: &Subject) -> io::Result<SearchResult> {
        let res = self.search_impl(subject);
        self.count += 1;
        res
    }

    /// Return a mutable reference to the underlying printer.
    pub fn get_mut(&mut self) -> &mut W {
        match self.printer {
            Printer::Standard(ref mut p) => p.get_mut(),
            Printer::Summary(ref mut p) => p.get_mut(),
            Printer::JSON(ref mut p) => p.get_mut(),
        }
    }

    /// Write a file separator to the underlying writer if and only if the
    /// following conditions are met:
    ///
    /// 1. This worker has been configured with a separator.
    /// 2. The `Standard` printer is being used.
    /// 3. A previous search has written at least one byte to the output.
    pub fn write_separator_file(&mut self) -> io::Result<()> {
        let sep = match self.config.separator_file {
            None => return Ok(()),
            Some(ref sep) => sep,
        };
        if let Printer::Standard(ref mut p) = self.printer {
            if p.has_written() {
                let mut wtr = p.get_mut();
                wtr.write_all(sep)?;
                wtr.write_all(self.searcher.line_terminator().as_bytes())?;
            }
        }
        Ok(())
    }

    /// Search the given subject using the appropriate strategy.
    fn search_impl(&mut self, subject: &Subject) -> io::Result<SearchResult> {
        let path = subject.path();
        if subject.is_stdin() {
            let stdin = io::stdin();
            // A `return` here appeases the borrow checker. NLL will fix this.
            return self.search_reader(path, stdin.lock());
        } else if self.config.preprocessor.is_some() {
            let cmd = self.config.preprocessor.clone().unwrap();
            let rdr = PreprocessorReader::from_cmd_path(cmd, path)?;
            self.search_reader(path, rdr)
        } else if self.config.search_zip && is_compressed(path) {
            match DecompressionReader::from_path(path) {
                None => Ok(SearchResult::default()),
                Some(rdr) => self.search_reader(path, rdr),
            }
        } else {
            self.search_path(path)
        }
    }

    /// Search the contents of the given file path.
    fn search_path(&mut self, path: &Path) -> io::Result<SearchResult> {
        match self.printer {
            Printer::Standard(ref mut p) => {
                let mut sink = p.sink_with_path(&self.matcher, path);
                self.searcher.search_path(&self.matcher, path, &mut sink)?;
                Ok(SearchResult {
                    nth: self.count,
                    has_match: sink.has_match(),
                    binary_byte_offset: sink.binary_byte_offset(),
                    stats: sink.stats().map(|s| s.clone()),
                })
            }
            Printer::Summary(ref mut p) => {
                let mut sink = p.sink_with_path(&self.matcher, path);
                self.searcher.search_path(&self.matcher, path, &mut sink)?;
                Ok(SearchResult {
                    nth: self.count,
                    has_match: sink.has_match(),
                    binary_byte_offset: sink.binary_byte_offset(),
                    stats: sink.stats().map(|s| s.clone()),
                })
            }
            Printer::JSON(ref mut p) => {
                let mut sink = p.sink_with_path(&self.matcher, path);
                self.searcher.search_path(&self.matcher, path, &mut sink)?;
                Ok(SearchResult {
                    nth: self.count,
                    has_match: sink.has_match(),
                    binary_byte_offset: sink.binary_byte_offset(),
                    stats: Some(sink.stats().clone()),
                })
            }
        }
    }

    /// Executes a search on the given reader, which may or may not correspond
    /// directly to the contents of the given file path. Instead, the reader
    /// may actually cause something else to be searched (for example, when
    /// a preprocessor is set or when decompression is enabled). In those
    /// cases, the file path is used for visual purposes only.
    ///
    /// Generally speaking, this method should only be used when there is no
    /// other choice. Searching via `search_path` provides more opportunities
    /// for optimizations (such as memory maps).
    fn search_reader<R: io::Read>(
        &mut self,
        path: &Path,
        rdr: R,
    ) -> io::Result<SearchResult> {
        match self.printer {
            Printer::Standard(ref mut p) => {
                let mut sink = p.sink_with_path(&self.matcher, path);
                self.searcher.search_reader(&self.matcher, rdr, &mut sink)?;
                Ok(SearchResult {
                    nth: self.count,
                    has_match: sink.has_match(),
                    binary_byte_offset: sink.binary_byte_offset(),
                    stats: sink.stats().map(|s| s.clone()),
                })
            }
            Printer::Summary(ref mut p) => {
                let mut sink = p.sink_with_path(&self.matcher, path);
                self.searcher.search_reader(&self.matcher, rdr, &mut sink)?;
                Ok(SearchResult {
                    nth: self.count,
                    has_match: sink.has_match(),
                    binary_byte_offset: sink.binary_byte_offset(),
                    stats: sink.stats().map(|s| s.clone()),
                })
            }
            Printer::JSON(ref mut p) => {
                let mut sink = p.sink_with_path(&self.matcher, path);
                self.searcher.search_reader(&self.matcher, rdr, &mut sink)?;
                Ok(SearchResult {
                    nth: self.count,
                    has_match: sink.has_match(),
                    binary_byte_offset: sink.binary_byte_offset(),
                    stats: Some(sink.stats().clone()),
                })
            }
        }
    }
}
