
#[derive(Clone, Debug, Default)]
pub struct DumpField {
    pub key: &'static str,
    pub value: String,
    pub comment: Option<&'static str>,
}

impl DumpField {
    pub fn new(
        key: &'static str,
        value: String,
        comment: Option<&'static str>
    ) -> DumpField {
        return DumpField { key, value, comment };
    }
}

#[derive(Clone, Debug)]
pub enum DumpRawData {
    None(),
    Bytes(Vec<u8>),
    Code(Vec<String>),
}

impl Default for DumpRawData {
    fn default() -> DumpRawData {
        return DumpRawData::None();
    }
}

#[derive(Clone, Debug, Default)]
pub struct Dump {
    label: String,
    fields: Vec<DumpField>,
    children: Vec<Dump>,
    raw_data: DumpRawData,
}

impl Dump {
    pub fn new(label: &str) -> Dump {
        let mut dump = Dump::default();
        dump.label = String::from(label);
        return dump;
    }

    pub fn push_field(
        &mut self,
        key: &'static str,
        value: String,
        comment: Option<&'static str>,
    ) {
        self.fields.push(DumpField::new(key, value, comment));
    }

    pub fn push_child(
        &mut self,
        dump: Dump
    ) {
        self.children.push(dump);
    }

    pub fn set_raw_data(
        &mut self,
        raw_data: DumpRawData
    ) {
        self.raw_data = raw_data;
    }

    pub fn iter_fields(&self) -> std::slice::Iter<'_, DumpField> {
        return self.fields.iter();
    }

    pub fn iter_children(&self) -> std::slice::Iter<'_, Dump> {
        return self.children.iter();
    }

    pub fn label(&self) -> &str {
        return self.label.as_str();
    }

    pub fn fields_align(&self) -> usize {
        return self
            .iter_fields()
            .max_by(|a, b| a.key.len().cmp(&b.key.len()))
            .map(|v| v.key.len())
            .unwrap_or(0) + 1;
    }

    #[rustfmt::skip]
    pub fn print(&self, indent_level: usize, indent_size: usize) {
        let indent = indent_level * indent_size;

        println!("{:>width$}{}", "", self.label, width = indent);

        let fields_indent = (indent_level + 1) * indent_size;
        let fields_align = self.fields_align();

        for field in self.fields.iter() {
            let label = field.key;

            if label.len() == 0 {
                println!(
                    "{:>width$}{}",
                    "",
                    field.value,
                    width = fields_indent);
            } else {
                println!(
                    "{:>width$}{label:<align$}: {}",
                    "",
                    field.value,
                    width = fields_indent,
                    align = fields_align);
            }
        }

        match &self.raw_data {
            DumpRawData::Code(code) => {
                for loc in code.iter() {
                    println!("{:>width$}{}", "", loc, width = fields_indent);
                }
            },
            _ => {},
        }

        for child in self.children.iter() {
            child.print(indent_level + 1, indent_size);
        }
    }
}
