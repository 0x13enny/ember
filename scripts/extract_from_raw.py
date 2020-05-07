import lief
import json

class Extractor():
	def __init__(self):

		self.binary = lief.parse("00552355331eefcab8898d82c621aec5df0ae25cee09644ce4087da93a4a49f6")
		j = "00552355331eefcab8898d82c621aec5df0ae25cee09644ce4087da93a4a49f6.jsonl"

		with open(j, 'r') as json_file:
		    json_list =json_file.read()

		self.result = [json.loads(jline) for jline in json_list.split('\n')][0] 

		# self.sections = self.binary.sections
	# for key, item in result.items():
	# 	print(key)

	# print(result['imports'])
	def export_json(self):
		json_data = json.loads(lief.to_json(self.binary))
		import_table = json_data['imports']
		print(import_table)
		for lib in import_table:
			# print(lib)
			for func in lib['entries']:
				print(func['name'])
		# print(type(json.dumps(json_data, sort_keys=True, indent=4)))

	def run(self):
		
		print(self.result.keys())
		print(self.result['section'])
		print(self.binary)
		# self.import_features()
		# self.export_features()
		# self.string_features()
		# self.section_features()
		# self.export_json()

	def string_features(self):

		# print(self.binary.data_directory(lief.PE.ResourcesManager.has_manifest))
		# lief.PE.RESOURCE_TYPES.STRING
		for sect in self.binary.sections:
			print(sect.name)
			print(sect.search_all("*"))

	def section_features(self):

		self.sections = {'entry': "", 'sections':[]}
		for sect in self.binary.sections:
			single_section = {"name":sect.name,
					   		  "size":sect.size,
					   		  "entropy":sect.entropy,
					   		  "vsize":sect.virtual_size,
					   		  "props":sect.characteristics_lists}
			self.sections['sections'].append(single_section)

	def data_directory(self):

		if self.binary.has_resources:
			rsrc_directory = self.binary.data_directory(lief.PE.DATA_DIRECTORY.RESOURCE_TABLE)
			if rsrc_directory.has_section:
				print(rsrc_directory.section)

	def import_features(self):

		self.imports = {}
		for imported_library in self.binary.imports:
			# print("Library name: " + imported_library.name)
			self.imports.update({imported_library.name : []})
			# if imported_library.name == "KERNEL32.dll":
			for func in imported_library.entries:
				self.imports[imported_library.name].append(func.name)
		
		# print(binary.sections)
				# print(func.name)
				    # if not func.is_ordinal:
				      # print(func.name)
				    # print(func.iat_address)
		# print(self.imports)		

	def export_features(self):

		self.exports = {}
		for exported_library in self.binary.exports:
			# print("Library name: " + imported_library.name)
			self.exports.update({exported_library.name : []})
			# if imported_library.name == "KERNEL32.dll":
			for func in exported_library.entries:
				self.exports[exported_library.name].append(func.name)
		print(self.exports)
	# dll = lief.parse("kernel32.dll")

	# for i in dll.exported_functions:
	# 	if i.name == "GetCurrentProcessId":
	# 		print(i.name, i.address)
if __name__=="__main__":
	ex = Extractor()
	ex.run()