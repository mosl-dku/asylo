/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "asylo/examples/grpc_server/translator_server_impl.h"

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "include/grpcpp/grpcpp.h"

namespace examples {
namespace grpc_server {

TranslatorServerImpl::TranslatorServerImpl()
    : Service(),
      // Initialize the translation map with a few known translations.
      translation_map_({{"asylo", "sanctuary"},
                        {"istio", "sail"},
                        {"kubernetes", "helmsman"}}) {}

::grpc::Status TranslatorServerImpl::GetTranslation(
    ::grpc::ServerContext *context, const GetTranslationRequest *request,
    GetTranslationResponse *response) {
  // Confirm that |*request| has an |input_word| field.
  if (!request->has_input_word()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "No input word given");
  }

  // Confirm that the translation map has a translation for the input word.
  auto response_iterator =
      translation_map_.find(absl::AsciiStrToLower(request->input_word()));
  if (response_iterator == translation_map_.end()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          absl::StrCat("No known translation for \"",
                                       request->input_word(), "\""));
  }

  // Return the translation.
  response->set_translated_word(response_iterator->second);
  return ::grpc::Status::OK;
}

double **matrix1, **matrix2, **matrix_result;
std::string output;

int row_mat1, row_mat2;
int col_mat1, col_mat2;

void TranslatorServerImpl::split(const std::string &str, std::vector<std::string> &vect, char ch)
{
	int pos = str.find(ch);
	int initialPos = 0;
	int count = 0;
	vect.clear();
	
	while (pos != std::string::npos)	{
		vect.push_back(str.substr(initialPos, pos - initialPos));
		count++;
		initialPos = pos + 1;

		pos = str.find(ch, initialPos);
	}
	int min = (pos < str.size()) ? pos : str.size();
	vect.push_back(str.substr(initialPos, min - initialPos + 1));
	count++;
}

void TranslatorServerImpl::getDim(std::string size, int &count_rows, int &count_columns)
{
	std::vector<std::string> vect_shape;
	split(size, vect_shape, ',');
	count_rows = atoi(vect_shape[0].erase(0, 1).c_str());
	count_columns = atoi(vect_shape[1].erase((vect_shape[1].length() - 1), 1).c_str());
}

double **TranslatorServerImpl::getMat(std::string size, std::vector<double> input, int &count_rows, int &count_columns)
{
	double **ary;
	ary = new double *[count_rows];
	
  for (int i = 0; i < count_rows; ++i)
		ary[i] = new double[count_columns];

	std::vector<double> vect_values = input;

	for (int row = 0; row < count_rows; row++){
		for (int column = 0; column < count_columns; column++){
			ary[row][column] = input[count_columns * row + column];
		}
	}

	return ary;
}

double **TranslatorServerImpl::transpose(std::vector<double> input, int &count_rows, int &count_columns)
{
	double **ary;
	int temp;
	temp = count_rows;
	count_rows = count_columns;
	count_columns = temp;
  ary = new double *[count_rows];
	std::vector<double> vect_values = input;

  for (int i = 0; i < count_rows; ++i)
		ary[i] = new double[count_columns];

	for (int row = 0; row < count_rows; row++){
		for (int column = 0; column < count_columns; column++){
			ary[row][column] = input[row + count_columns * column];
		}
	}
	return ary;
}

double **TranslatorServerImpl::matmul(double **input_mat1, double **input_mat2)
{
	double **result_mat;
  result_mat = new double *[row_mat1];

	for (int i = 0; i < row_mat1; i++){
		result_mat[i] = new double[col_mat2];
	}

	double _temp = 0;

	for (int i = 0; i < row_mat1; i++){
		for (int j = 0; j < col_mat2; j++){
			for (int k = 0; k < col_mat1; k++){
				_temp += (input_mat1[i][k] * input_mat2[k][j]);
			}
			result_mat[i][j] = _temp;
			_temp = 0;
		}
	}
	return result_mat;
}

void TranslatorServerImpl::getOutput()
{
	output = "";

	for (int i = 0; i < row_mat1; i++){
		output += "[";
		for (int j = 0; j < col_mat2 - 1; j++){
			output += std::to_string(matrix_result[i][j]) + " ";
		}
		output += std::to_string(matrix_result[i][col_mat2 - 1]);
		output += "]";
	}
}

void TranslatorServerImpl::setOutput(GetMatmulResponse *response)
{
	for (int i = 0; i < row_mat1; i++){
		for (int j = 0; j < col_mat2; j++)
			response->add_result(matrix_result[i][j]); //add each result to response var
	}
}

void TranslatorServerImpl::deleteMemory()
{
	for (int i = 0; i < row_mat1; i++){
		delete[] matrix1[i];
    delete[] matrix_result[i];
	}

	for (int i = 0; i < row_mat2; i++){
		delete[] matrix2[i];
	}
}

::grpc::Status TranslatorServerImpl::MatMul(
	::grpc::ServerContext *context, const GetMatMulRequest *request,
	GetMatmulResponse *response)
{
	context->set_compression_algorithm(GRPC_COMPRESS_GZIP);

	row_mat1 = 0;
	col_mat1 = 0;
	row_mat2 = 0;
	col_mat2 = 0;

	std::string input_size1 = request->tensor1_shape();
	std::string input_size2 = request->tensor2_shape();
	std::vector<double> input_str1;
	std::vector<double> input_str2;
	getDim(input_size1, row_mat1, col_mat1);
	getDim(input_size2, row_mat2, col_mat2);


	for (int i = 0; i < row_mat1 * col_mat1; i++)
		input_str1.push_back(request->tensor1(i));
	for (int i = 0; i < row_mat2 * col_mat2; i++)
		input_str2.push_back(request->tensor2(i));
	
	if (col_mat1 != row_mat2){
		if (col_mat1 == col_mat2){
			matrix1 = getMat(input_size1, input_str1, row_mat1, col_mat1);
			matrix2 = transpose(input_str2, row_mat2, col_mat2);
		}
		else if (row_mat2 == row_mat1){
			matrix1 = transpose(input_str1, row_mat1, col_mat1);
			matrix2 = getMat(input_size2, input_str2, row_mat2, col_mat2);
		}
	}
	else{
		matrix1 = getMat(input_size1, input_str1, row_mat1, col_mat1);
		matrix2 = getMat(input_size2, input_str2, row_mat2, col_mat2);
	}

	matrix_result = new double *[row_mat1];
	
  for (int j = 0; j < row_mat1; ++j){
		matrix_result[j] = new double[col_mat2];
		for (int i = 0; i < col_mat2; i++)
			memset(&matrix_result[j][i], 0, sizeof(matrix_result[j][i]));
	}

	matrix_result = matmul(matrix1, matrix2);

	if (matrix_result != NULL){
		setOutput(response);
	}
	else{
		std::cout << "matrix_result is NULL" << std::endl;
		output = " ";
	}
	deleteMemory();
	return ::grpc::Status::OK;
}

}  // namespace grpc_server
}  // namespace examples
