const filename = request.query.file;

const data = fs.readFileSync(filename);