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

#include "asylo/examples/grpc_server2/translator_server_impl.h"

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

double x[2][5]={{1,0,3,0,5},{0,2,0,4,0}};
double y[1][5] = {1,2,3,4,5};

double **matrix_result, **transposed_x;
int count =0;


double **w;
double *b;
std::string output;

int w_row, w_col;
int x_row, x_col;
int y_row, y_col;
int b_size;

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

void TranslatorServerImpl::getDim(std::string size, int &vec_size)
{
	std::vector<std::string> vec_shape;
	split(size, vec_shape, ',');
	vec_size = atoi(vec_shape[0].erase(0,1).c_str());
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
			std::cout<<ary[row][column]<<" ";
		}
		std::cout<<"\n";
	}

	return ary;
}

double *TranslatorServerImpl::getVec(std::vector<double> input, int vec_size)
{
	double *ary = new double [vec_size];
	for (int i = 0; i<vec_size;i++)
		ary[i] = input[i];
	
	return ary;
}

double **TranslatorServerImpl::transpose(double input[2][5], int count_rows, int count_columns)
{
	double **ary;
  ary = new double *[count_columns];


  for (int i = 0; i < count_columns; ++i)
		ary[i] = new double[count_rows];

	for (int row = 0; row < count_columns; row++){
		for (int column = 0; column < count_rows; column++){
			ary[row][column] = input[column][row];
		}
	}
return ary;
}

double **TranslatorServerImpl::matmul(double** input_mat1, double input_mat2[2][5], int output_row, int output_col, int inner)
{
	double **result_mat;
  result_mat = new double *[output_row];

	for (int i = 0; i < output_row; i++){
		result_mat[i] = new double[output_col];
	}

	double _temp = 0;

	for (int i = 0; i < output_row; i++){
		for (int j = 0; j < output_col; j++){
			for (int k = 0; k < inner; k++){
				_temp += (input_mat1[i][k] * input_mat2[k][j]);
			}
			result_mat[i][j] = _temp;
			_temp = 0;
		}
	}
	return result_mat;
}

double **TranslatorServerImpl::matmul(double** input_mat1, double** input_mat2, int output_row, int output_col, int inner)
{
	double **result_mat;
  result_mat = new double *[output_row];

	for (int i = 0; i < output_row; i++){
		result_mat[i] = new double[output_col];
	}

	double _temp = 0;

	for (int i = 0; i < output_row; i++){
		for (int j = 0; j < output_col; j++){
			for (int k = 0; k < inner; k++){
				_temp += (input_mat1[i][k] * input_mat2[k][j]);
			}
			result_mat[i][j] = _temp;
			_temp = 0;
		}
	}
	return result_mat;
}

void TranslatorServerImpl::matadd(double **input_mat1, double *vec, int mat_row, int mat_col)
{
	for(int i = 0; i<mat_row;i++)
	{
		for(int j = 0; j < mat_col; j++)
		{
			input_mat1[i][j] += vec[0];
		}
	}
}

void TranslatorServerImpl::matsub(double **input_mat1, double vec[1][5], int mat_row, int mat_col)
{
	for(int i = 0; i<mat_row;i++)
	{
		for(int j = 0; j < mat_col; j++)
		{
			input_mat1[i][j] -= vec[i][j];
		}
	}
}

void TranslatorServerImpl::getOutput()
{
}

void TranslatorServerImpl::setOutput(GetGradWResponse *response, int output_row, int output_col)
{
	std::cout<<"must be 1"<<std::endl;
	for (int i = 0; i < output_row; i++){
		for (int j = 0; j < output_col; j++)
		{
			matrix_result[i][j] = matrix_result[i][j];
			response->add_result(matrix_result[i][j]); //add each result to response var
		}
	}
}

void TranslatorServerImpl::deleteMemory()
{

}

::grpc::Status TranslatorServerImpl::GetGrad_W(
	::grpc::ServerContext *context, const GetGradWRequest *request,
	GetGradWResponse *response)
{
	context->set_compression_algorithm(GRPC_COMPRESS_GZIP);
	++count;
	std::cout<<"-----------------------------"<<count<<" called-------------------------------------"<<std::endl;
	std::string w_size_str = request->tensor1_shape();
	std::string b_size_str = request->tensor2_shape();
	std::string x_size_str = "[2,5]";
	std::string y_size_str = "[1,5]";
	std::vector<double> w_input;
	std::vector<double> x_input;
	std::vector<double> b_input;
	std::vector<double> y_input;
	std::cout<<w_size_str<<b_size_str<<std::endl;

	getDim(w_size_str, w_row, w_col);
	getDim(x_size_str, x_row, x_col);
	getDim(y_size_str, y_row, y_col);
	getDim(b_size_str, b_size);

	for (int i = 0; i < w_row * w_col; i++){
		w_input.push_back(request->tensor1(i));
	}
	for (int i = 0; i < b_size ; i++){
		b_input.push_back(request->tensor2(i));
	}
	
	w = getMat(w_size_str, w_input, w_row, w_col);
	//b = getVec(b_input, b_size);
	

	//matrix_result = matmul(w, x,1,5,2);
	//matadd(matrix_result, b, 1, 5);
	//matsub(w, y, 1, 5);
	//for(int i =0; i<5;i++)
	//std::cout<<matrix_result[0][i];
	if(transposed_x==NULL)
	transposed_x = transpose(x,2,5);

	matrix_result = matmul(w,transposed_x,1,2,5);
	//std::cout<<matrix_result[0][i]<<std::endl;

	if (matrix_result != NULL){
		setOutput(response,1,2);
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
