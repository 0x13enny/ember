
import sys, csv, json, argparse
# add custom ember path
sys.path.append("/home/benny/Research/ember")
sys.path.append("/home/benny/ember")
import ember
import numpy as np



def main():
	prog = "python3 extractor_from_bin.py"
	descr = "extract high level features from binary files"
	parser = argparse.ArgumentParser(prog=prog, description=descr)
	# parser.add_argument("-v", "--featureversion", type=int, default=2, help="EMBER feature version")
	parser.add_argument("source_csv", metavar="SOURCE_DIR", type=str, help="Directory with raw features")
	parser.add_argument("dest_json", metavar="DEST_DIR", type=str, default="data.json",help="Directory with raw features")
	# parser.add_argument("--optimize", help="gridsearch to find best parameters", action="store_true")
	args = parser.parse_args()

	E = ember.PEFeatureExtractor()

	with open(args.source_csv, newline='') as f:
		reader = csv.reader(f)
		docs = list(reader)
	f.close()


	# docs = [['00552355331eefcab8898d82c621aec5df0ae25cee09644ce4087da93a4a49f6','1'],['kernel32.dll','0']]

	with open(args.dest_json, 'w') as j_file:
		for path, label in docs:
			with open(path, 'rb') as f:
			    bytes_array = np.array(bytearray(f.read()), dtype="uint8")
			f.close()
			raw = E.raw_features(bytes_array, path,label=int(label))

			j_file.write(json.dumps(raw) + "\n")

	j_file.close()

if __name__ == "__main__":
	main()