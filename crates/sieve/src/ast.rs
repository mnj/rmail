//! Typed representation of a compiled script.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rel {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparator {
    AsciiCasemap,
    Octet,
    AsciiNumeric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Is,
    Contains,
    Matches,
    Count(Rel),
    Value(Rel),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub kind: MatchKind,
    pub cmp: Comparator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrPart {
    All,
    LocalPart,
    Domain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Test {
    True,
    False,
    Not(Box<Test>),
    AllOf(Vec<Test>),
    AnyOf(Vec<Test>),
    Exists(Vec<String>),
    Header {
        names: Vec<String>,
        keys: Vec<String>,
        m: Match,
    },
    Address {
        part: AddrPart,
        names: Vec<String>,
        keys: Vec<String>,
        m: Match,
    },
    Envelope {
        part: AddrPart,
        names: Vec<String>,
        keys: Vec<String>,
        m: Match,
    },
    Size {
        over: bool,
        limit: u64,
    },
    Body {
        keys: Vec<String>,
        m: Match,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vacation {
    pub reason: String,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub days: u32,
    pub addresses: Vec<String>,
    pub mime: bool,
    pub handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    If {
        cond: Test,
        then: Vec<Cmd>,
        otherwise: Vec<Cmd>,
    },
    Keep {
        flags: Option<Vec<String>>,
    },
    Discard,
    Stop,
    FileInto {
        folder: String,
        copy: bool,
        flags: Option<Vec<String>>,
    },
    Redirect {
        address: String,
        copy: bool,
    },
    SetFlag(Vec<String>),
    AddFlag(Vec<String>),
    RemoveFlag(Vec<String>),
    Vacation(Vacation),
}
